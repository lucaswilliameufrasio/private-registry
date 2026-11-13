package artifacts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"private-registry/internal/backup"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/repositories"
	"private-registry/internal/spikes/sqlitebackup"
	"private-registry/internal/storage"
)

func TestPartialRecoveryRejectsCargoVersionsWithoutChangingSource(t *testing.T) {
	for _, kind := range []string{"version", "receipt", "published"} {
		t.Run(kind, func(t *testing.T) {
			exercisePartialRecoveryRejectsCargo(t, kind)
		})
	}
}

func TestIsolatedCargoRecoveryRequiresExactSet(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	source, err := storage.NewFileSystem(filepath.Join(root, "source"))
	if err != nil {
		t.Fatal(err)
	}
	remote, err := storage.NewFileSystem(filepath.Join(root, "remote"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("synthetic Cargo object")
	object, err := source.Put(ctx, fixture.workspaceID, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	user, repository := fixture.userIDs["publisher"], uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'cargo-recovery', 'Cargo', ?, 'now', 'now', 'cargo')`, repository, fixture.workspaceID, user); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, fixture.userIDs["owner"], fixture.workspaceID, repository, user, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	token, err := fixture.repositoryService.IssueCargoWriteToken(ctx, user, fixture.workspaceID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := cargo.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := service.Reserve(ctx, token.Bearer, fixture.workspaceID, repository, cargo.PublishFrame{Metadata: []byte(`{"name":"fixture","vers":"1.0.0","deps":[],"features":{}}`), Size: object.Size, SHA256: object.Key.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET status = 'uploading', upload_claim_id = ? WHERE reservation_id = ?`, uuid.NewString(), reservation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET status = 'uploaded', upload_claim_id = NULL, object_verified = 1, index_entry = '{}' WHERE reservation_id = ?`, reservation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PublishReceipt(ctx, token.Bearer, fixture.workspaceID, repository, reservation.ID); err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(root, "snapshot.sqlite")
	if _, err := sqlitebackup.Snapshot(ctx, fixture.db, snapshotPath, sqlitebackup.Options{PagesPerStep: 16}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	var installation string
	if err := fixture.db.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&installation); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := backup.GenericSetRecovery{Signer: public, InstallationID: installation, BackupID: uuid.NewString(), SnapshotSHA256: hex.EncodeToString(digest[:])}
	empty := backup.GenericSet{Version: 1, InstallationID: installation, BackupID: trust.BackupID, SnapshotSHA256: trust.SnapshotSHA256, Objects: []backup.ObjectReceipt{}}
	genericSet, err := backup.SignGenericSet(empty, private)
	if err != nil {
		t.Fatal(err)
	}
	goSet, err := backup.SignGoSet(backup.GoSet(empty), private)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(root, "staging")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stage := func() (backup.RecoveryStage, error) {
		file, err := os.CreateTemp(stageDir, "owned-")
		if err != nil {
			return nil, err
		}
		return syntheticRecoveryStage{File: file}, nil
	}
	cargoTrust := trust
	cargoTrust.Inventory = []backup.GenericObject{{Key: object.Key, Size: object.Size}}
	captured, err := backup.CaptureCargoSet(ctx, cargoTrust, source, remote, identity.Recipient(), private, 4096, stage)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := backup.VerifyObjectReceipt(captured.Receipts[0], public, installation, trust.BackupID)
	if err != nil {
		t.Fatal(err)
	}
	sources := []backup.RecoveryObjectSource{{Receipt: captured.Receipts[0], Open: func(ctx context.Context) (io.ReadCloser, error) {
		reader, _, err := remote.Open(ctx, storage.ObjectKey{WorkspaceID: receipt.WorkspaceID, SHA256: receipt.CipherSHA256})
		return reader, err
	}}}
	var encrypted bytes.Buffer
	if _, err := backup.EncryptSnapshot(ctx, bytes.NewReader(snapshot), &encrypted, 64<<20, 65<<20, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "recovery")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	prepare := func(name string, inputs []backup.RecoveryObjectSource) (backup.PreparedSQLiteRecovery, error) {
		return backup.PrepareEncryptedSQLiteCargoRecovery(ctx, bytes.NewReader(encrypted.Bytes()), 65<<20, 64<<20, 10, 10, genericSet, trust, goSet, trust, captured.Set, cargoTrust, parent, name, nil, nil, inputs, identity, stage)
	}
	if result, err := prepare("missing", nil); err == nil || result.DatabasePath != "" {
		t.Fatal("missing Cargo object was accepted")
	}
	if _, err := os.Stat(filepath.Join(parent, "missing", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal(err)
	}
	wrongSet, err := backup.SignCargoSet(backup.CargoSet(empty), private)
	if err != nil {
		t.Fatal(err)
	}
	wrongResult, err := backup.PrepareEncryptedSQLiteCargoRecovery(ctx, bytes.NewReader(encrypted.Bytes()), 65<<20, 64<<20, 10, 10, genericSet, trust, goSet, trust, wrongSet, cargoTrust, parent, "wrong-inventory", nil, nil, nil, identity, stage)
	if err == nil || wrongResult.DatabasePath != "" {
		t.Fatal("Cargo recovery accepted a signed set missing a snapshot object")
	}
	if _, err := os.Stat(filepath.Join(parent, "wrong-inventory", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepare("restored", sources)
	if err != nil || prepared.CargoObjects != 1 {
		t.Fatalf("Cargo recovery: %+v %v", prepared, err)
	}
	if _, err := os.Stat(filepath.Join(parent, "restored", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal(err)
	}
	recoveredDB, err := database.Open(ctx, config.Config{DataDir: filepath.Join(parent, "restored"), DatabaseDriver: config.SQLite, DatabaseDSN: prepared.DatabasePath, DatabaseMaxOpenConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	var invalidated int
	err = recoveredDB.QueryRowContext(ctx, `SELECT recovery_invalidated FROM registry_cargo_reservations WHERE reservation_id = ?`, reservation.ID).Scan(&invalidated)
	if err != nil || invalidated != 1 {
		_ = recoveredDB.Close()
		t.Fatalf("recovered Cargo reservation was not invalidated: %d %v", invalidated, err)
	}
	recoveredRepositories, err := repositories.New(recoveredDB, config.SQLite)
	if err != nil {
		_ = recoveredDB.Close()
		t.Fatal(err)
	}
	if err := recoveredRepositories.WithCargoWriteTokenTransaction(ctx, token.Bearer, fixture.workspaceID, repository, func(_ *sql.Tx, _ string) error { return nil }); !errors.Is(err, repositories.ErrCargoWriteTokenUnavailable) {
		_ = recoveredDB.Close()
		t.Fatalf("recovered Cargo write credential remained usable: %v", err)
	}
	if err := recoveredDB.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := storage.NewFileSystem(filepath.Join(parent, "restored", "object-store"))
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := backup.CopyGenericObject(ctx, restored, cargoTrust.Inventory[0], &got); err != nil || !bytes.Equal(got.Bytes(), data) {
		t.Fatalf("restored Cargo object: %v", err)
	}
	got.Reset()
	if err := backup.CopyGenericObject(ctx, source, cargoTrust.Inventory[0], &got); err != nil || !bytes.Equal(got.Bytes(), data) {
		t.Fatalf("source Cargo object changed during recovery: %v", err)
	}
}

func exercisePartialRecoveryRejectsCargo(t *testing.T, kind string) {
	t.Helper()
	fixture := newArtifactFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	user := fixture.userIDs["publisher"]
	repository, packageID, versionID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'synthetic-cargo', 'Synthetic Cargo', ?, 'now', 'now', 'cargo')`, repository, fixture.workspaceID, user); err != nil {
		t.Fatal(err)
	}
	if kind == "version" {
		for _, item := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO registry_cargo_packages (package_id, workspace_id, repository_id, name, name_identity, created_by, created_at) VALUES (?, ?, ?, 'fixture', 'fixture', ?, 'now')`, []any{packageID, fixture.workspaceID, repository, user}},
			{`INSERT INTO registry_cargo_versions (cargo_version_id, workspace_id, repository_id, package_id, version, version_identity, index_entry, archive_sha256, archive_size, created_by, created_at) VALUES (?, ?, ?, ?, '1.0.0', '1.0.0', '{}', ?, 12, ?, 'now')`, []any{versionID, fixture.workspaceID, repository, packageID, strings.Repeat("a", 64), user}},
		} {
			if _, err := fixture.db.ExecContext(ctx, item.query, item.args...); err != nil {
				t.Fatal(err)
			}
		}
	} else {
		if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, fixture.userIDs["owner"], fixture.workspaceID, repository, user, repositories.GrantPublisher); err != nil {
			t.Fatal(err)
		}
		token, err := fixture.repositoryService.IssueCargoWriteToken(ctx, user, fixture.workspaceID, repository, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		service, err := cargo.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
		if err != nil {
			t.Fatal(err)
		}
		reservation, err := service.Reserve(ctx, token.Bearer, fixture.workspaceID, repository, cargo.PublishFrame{Metadata: []byte(`{"name":"fixture","vers":"1.0.0","deps":[],"features":{}}`), Size: 12, SHA256: strings.Repeat("a", 64)})
		if err != nil {
			t.Fatal(err)
		}
		versionID = reservation.ID
		if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET status = 'uploading', upload_claim_id = ? WHERE reservation_id = ?`, uuid.NewString(), versionID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET status = 'uploaded', upload_claim_id = NULL, object_verified = 1, index_entry = '{}' WHERE reservation_id = ?`, versionID); err != nil {
			t.Fatal(err)
		}
		if kind == "published" {
			if _, err := service.PublishReceipt(ctx, token.Bearer, fixture.workspaceID, repository, versionID); err != nil {
				t.Fatal(err)
			}
		}
	}
	root := t.TempDir()
	snapshotPath := filepath.Join(root, "snapshot.sqlite")
	if _, err := sqlitebackup.Snapshot(ctx, fixture.db, snapshotPath, sqlitebackup.Options{PagesPerStep: 16}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	var installationID string
	if err := fixture.db.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&installationID); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	backupID := uuid.NewString()
	set := backup.GenericSet{Version: 1, InstallationID: installationID, BackupID: backupID, SnapshotSHA256: hex.EncodeToString(digest[:]), Objects: []backup.ObjectReceipt{}}
	envelope, err := backup.SignGenericSet(set, private)
	if err != nil {
		t.Fatal(err)
	}
	trusted := backup.GenericSetRecovery{Signer: public, InstallationID: installationID, BackupID: backupID, SnapshotSHA256: set.SnapshotSHA256}
	parent := filepath.Join(root, "recovery-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.PrepareSQLiteRecovery(ctx, bytes.NewReader(snapshot), 64<<20, 10, 10, envelope, trusted, parent, "incomplete"); err == nil || !strings.Contains(err.Error(), "Cargo") {
		t.Fatalf("partial recovery did not reject Cargo versions: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "incomplete", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal("failed recovery marker missing:", err)
	}
	var count int
	query := `SELECT count(*) FROM registry_cargo_versions WHERE cargo_version_id = ? AND archive_sha256 = ?`
	if kind == "receipt" || kind == "published" {
		query = `SELECT count(*) FROM registry_cargo_reservations WHERE reservation_id = ? AND archive_sha256 = ? AND status = 'uploaded' AND object_verified = 1`
	}
	if err := fixture.db.QueryRowContext(ctx, query, versionID, strings.Repeat("a", 64)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("source Cargo version changed: count=%d err=%v", count, err)
	}
	if kind == "published" {
		if err := fixture.db.QueryRowContext(ctx, `SELECT count(*) FROM registry_cargo_publications WHERE reservation_id = ?`, versionID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("source Cargo publication changed: count=%d err=%v", count, err)
		}
	}
}
