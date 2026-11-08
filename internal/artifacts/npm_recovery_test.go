package artifacts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"private-registry/internal/backup"
	"private-registry/internal/config"
	"private-registry/internal/npm"
	"private-registry/internal/repositories"
	"private-registry/internal/spikes/sqlitebackup"
)

func TestPartialRecoveryRejectsNPMVersionsWithoutChangingSource(t *testing.T) {
	for _, kind := range []string{"version", "receipt"} {
		t.Run(kind, func(t *testing.T) {
			exercisePartialRecoveryRejectsNPM(t, kind)
		})
	}
}

func exercisePartialRecoveryRejectsNPM(t *testing.T, kind string) {
	t.Helper()
	fixture := newArtifactFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner := fixture.userIDs["owner"]
	repository, pkg, version := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'npm-recovery', 'npm', ?, 'now', 'now', 'npm')`, repository, fixture.workspaceID, owner); err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512([]byte("synthetic"))
	if kind == "version" {
		if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_npm_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (?, ?, ?, 'fixture', ?, 'now')`, pkg, fixture.workspaceID, repository, owner); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_npm_versions (npm_version_id, workspace_id, repository_id, package_id, version, version_identity, manifest, tarball_sha256, tarball_size, integrity, created_by, created_at) VALUES (?, ?, ?, ?, '1.0.0', '1.0.0', '{}', ?, 9, ?, ?, 'now')`, version, fixture.workspaceID, repository, pkg, strings.Repeat("a", 64), "sha512-"+base64.StdEncoding.EncodeToString(digest[:]), owner); err != nil {
			t.Fatal(err)
		}
	} else {
		publisher := fixture.userIDs["publisher"]
		if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, fixture.workspaceID, repository, publisher, repositories.GrantPublisher); err != nil {
			t.Fatal(err)
		}
		token, err := fixture.repositoryService.IssueNPMWriteToken(ctx, publisher, fixture.workspaceID, repository, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		service, err := npm.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
		if err != nil {
			t.Fatal(err)
		}
		reservation, err := service.Reserve(ctx, token.Bearer, fixture.workspaceID, repository, npm.ReservationRequest{Name: "fixture", Version: "1.0.0", TarballSHA256: strings.Repeat("a", 64), TarballSize: 9, MetadataSHA256: strings.Repeat("b", 64)})
		if err != nil {
			t.Fatal(err)
		}
		version = reservation.ID
		if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_npm_reservations SET status = 'uploading', upload_claim_id = ? WHERE reservation_id = ?`, uuid.NewString(), version); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_npm_reservations SET status = 'uploaded', upload_claim_id = NULL, object_verified = 1, manifest = '{}', integrity = ? WHERE reservation_id = ?`, "sha512-"+base64.StdEncoding.EncodeToString(digest[:]), version); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	path := filepath.Join(root, "snapshot.sqlite")
	if _, err := sqlitebackup.Snapshot(ctx, fixture.db, path, sqlitebackup.Options{PagesPerStep: 16}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var installation string
	if err := fixture.db.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&installation); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(snapshot)
	set := backup.GenericSet{Version: 1, InstallationID: installation, BackupID: uuid.NewString(), SnapshotSHA256: hex.EncodeToString(hash[:]), Objects: []backup.ObjectReceipt{}}
	envelope, err := backup.SignGenericSet(set, private)
	if err != nil {
		t.Fatal(err)
	}
	trust := backup.GenericSetRecovery{Signer: public, InstallationID: installation, BackupID: set.BackupID, SnapshotSHA256: set.SnapshotSHA256}
	parent := filepath.Join(root, "recovery")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.PrepareSQLiteRecovery(ctx, bytes.NewReader(snapshot), 64<<20, 10, 10, envelope, trust, parent, "isolated"); err == nil || !strings.Contains(err.Error(), "npm") {
		t.Fatalf("partial recovery did not reject npm versions: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "isolated", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal("failed recovery marker missing:", err)
	}
	goSet, err := backup.SignGoSet(backup.GoSet(set), private)
	if err != nil {
		t.Fatal(err)
	}
	cargoSet, err := backup.SignCargoSet(backup.CargoSet(set), private)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if _, err := backup.EncryptSnapshot(ctx, bytes.NewReader(snapshot), &encrypted, 64<<20, 65<<20, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(root, "stage")
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
	for _, mode := range []string{"go", "cargo"} {
		var result backup.PreparedSQLiteRecovery
		var err error
		if mode == "go" {
			result, err = backup.PrepareEncryptedSQLiteGoRecovery(ctx, bytes.NewReader(encrypted.Bytes()), 65<<20, 64<<20, 10, 10, envelope, trust, goSet, trust, parent, mode, nil, nil, identity, stage)
		} else {
			result, err = backup.PrepareEncryptedSQLiteCargoRecovery(ctx, bytes.NewReader(encrypted.Bytes()), 65<<20, 64<<20, 10, 10, envelope, trust, goSet, trust, cargoSet, trust, parent, mode, nil, nil, nil, identity, stage)
		}
		if err == nil || !strings.Contains(err.Error(), "npm") || result.DatabasePath != "" {
			t.Fatalf("%s recovery did not reject npm versions: %v", mode, err)
		}
		if _, err := os.Stat(filepath.Join(parent, mode, "RECOVERY_INCOMPLETE")); err != nil {
			t.Fatalf("%s failed recovery marker missing: %v", mode, err)
		}
	}
	if entries, err := os.ReadDir(stageDir); err != nil || len(entries) != 0 {
		t.Fatalf("recovery staging not cleaned: %v", err)
	}
	var count int
	query := `SELECT count(*) FROM registry_npm_versions WHERE npm_version_id = ? AND tarball_sha256 = ?`
	if kind == "receipt" {
		query = `SELECT count(*) FROM registry_npm_reservations WHERE reservation_id = ? AND tarball_sha256 = ? AND status = 'uploaded' AND object_verified = 1`
	}
	if err := fixture.db.QueryRowContext(ctx, query, version, strings.Repeat("a", 64)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("source npm version changed: count=%d err=%v", count, err)
	}
}
