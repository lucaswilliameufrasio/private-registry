package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"private-registry/internal/backup"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/npm"
	"private-registry/internal/repositories"
	"private-registry/internal/spikes/sqlitebackup"
	"private-registry/internal/storage"
)

func TestIsolatedNPMRecoveryRequiresExactSet(t *testing.T) {
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
	manifest := []byte(`{"name":"fixture","version":"1.0.0"}`)
	var archiveBytes bytes.Buffer
	gz := gzip.NewWriter(&archiveBytes)
	archive := tar.NewWriter(gz)
	if err := archive.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	data := archiveBytes.Bytes()
	object, err := source.Put(ctx, fixture.workspaceID, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	user, repository := fixture.userIDs["publisher"], uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'npm-isolated-recovery', 'npm', ?, 'now', 'now', 'npm')`, repository, fixture.workspaceID, user); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, fixture.userIDs["owner"], fixture.workspaceID, repository, user, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, fixture.userIDs["owner"], fixture.workspaceID, repository, user, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	readToken, err := fixture.repositoryService.IssuePersonalReadToken(ctx, user, fixture.workspaceID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	token, err := fixture.repositoryService.IssueNPMWriteToken(ctx, user, fixture.workspaceID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := npm.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	metadata := sha256.Sum256(manifest)
	reservation, err := service.Reserve(ctx, token.Bearer, fixture.workspaceID, repository, npm.ReservationRequest{Name: "fixture", Version: "1.0.0", TarballSize: object.Size, TarballSHA256: object.Key.SHA256, MetadataSHA256: hex.EncodeToString(metadata[:])})
	if err != nil {
		t.Fatal(err)
	}
	receiptStage := filepath.Join(root, "receipt-stage")
	if err := os.Mkdir(receiptStage, 0o700); err != nil {
		t.Fatal(err)
	}
	receiver, err := npm.NewReceiptService(fixture.db, fixture.repositoryService, config.SQLite, source, npm.ReceiptOptions{StagingDirectory: receiptStage, MaxConcurrent: 1, Limits: npm.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	integrity := sha512.Sum512(data)
	publication := npm.PublishDocument{Name: "fixture", Version: "1.0.0", Manifest: manifest, Size: object.Size, Integrity: "sha512-" + base64.StdEncoding.EncodeToString(integrity[:])}
	if err := receiver.Receive(ctx, token.Bearer, fixture.workspaceID, repository, reservation.ID, publication, bytes.NewReader(data)); err != nil {
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
	cargoSet, err := backup.SignCargoSet(backup.CargoSet(empty), private)
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
	npmTrust := trust
	npmTrust.Inventory = []backup.GenericObject{{Key: object.Key, Size: object.Size}}
	captured, err := backup.CaptureNPMSet(ctx, npmTrust, source, remote, identity.Recipient(), private, 4096, stage)
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
		return backup.PrepareEncryptedSQLiteNPMRecovery(ctx, bytes.NewReader(encrypted.Bytes()), 65<<20, 64<<20, 10, 10, genericSet, trust, goSet, trust, cargoSet, trust, captured.Set, npmTrust, parent, name, nil, nil, nil, inputs, identity, stage)
	}
	wrongIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if result, err := backup.PrepareEncryptedSQLiteNPMRecovery(ctx, bytes.NewReader(encrypted.Bytes()), 65<<20, 64<<20, 10, 10, genericSet, trust, goSet, trust, cargoSet, trust, captured.Set, npmTrust, parent, "wrong-key", nil, nil, nil, sources, wrongIdentity, stage); err == nil || result.DatabasePath != "" {
		t.Fatal("npm recovery accepted the wrong decryption identity")
	}
	if _, err := os.Stat(filepath.Join(parent, "wrong-key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong recovery key created destination: %v", err)
	}
	wrongTrust := npmTrust
	wrongTrust.BackupID = uuid.NewString()
	if result, err := backup.PrepareEncryptedSQLiteNPMRecovery(ctx, bytes.NewReader(encrypted.Bytes()), 65<<20, 64<<20, 10, 10, genericSet, trust, goSet, trust, cargoSet, trust, captured.Set, wrongTrust, parent, "wrong-context", nil, nil, nil, sources, identity, stage); err == nil || result.DatabasePath != "" {
		t.Fatal("npm recovery accepted mismatched trust context")
	}
	if _, err := os.Stat(filepath.Join(parent, "wrong-context")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong npm trust context created destination: %v", err)
	}
	if result, err := prepare("missing", nil); err == nil || result.DatabasePath != "" {
		t.Fatal("missing NPM object was accepted")
	}
	if _, err := os.Stat(filepath.Join(parent, "missing", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal(err)
	}
	wrongSet, err := backup.SignNPMSet(backup.NPMSet(empty), private)
	if err != nil {
		t.Fatal(err)
	}
	wrongResult, err := backup.PrepareEncryptedSQLiteNPMRecovery(ctx, bytes.NewReader(encrypted.Bytes()), 65<<20, 64<<20, 10, 10, genericSet, trust, goSet, trust, cargoSet, trust, wrongSet, npmTrust, parent, "wrong-inventory", nil, nil, nil, nil, identity, stage)
	if err == nil || wrongResult.DatabasePath != "" {
		t.Fatal("NPM recovery accepted a signed set missing a snapshot object")
	}
	if _, err := os.Stat(filepath.Join(parent, "wrong-inventory", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepare("restored", sources)
	if err != nil || prepared.NPMObjects != 1 {
		t.Fatalf("NPM recovery: %+v %v", prepared, err)
	}
	if _, err := os.Stat(filepath.Join(parent, "restored", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal(err)
	}
	if result, err := prepare("restored", sources); err == nil || result.DatabasePath != "" {
		t.Fatal("npm recovery reused an existing destination")
	}
	recoveredDB, err := database.Open(ctx, config.Config{DataDir: filepath.Join(parent, "restored"), DatabaseDriver: config.SQLite, DatabaseDSN: prepared.DatabasePath, DatabaseMaxOpenConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	var invalidated int
	err = recoveredDB.QueryRowContext(ctx, `SELECT recovery_invalidated FROM registry_npm_reservations WHERE reservation_id = ?`, reservation.ID).Scan(&invalidated)
	if err != nil || invalidated != 1 {
		_ = recoveredDB.Close()
		t.Fatalf("recovered NPM reservation was not invalidated: %d %v", invalidated, err)
	}
	recoveredRepositories, err := repositories.New(recoveredDB, config.SQLite)
	if err != nil {
		_ = recoveredDB.Close()
		t.Fatal(err)
	}
	if err := recoveredRepositories.WithNPMWriteTokenTransaction(ctx, token.Bearer, fixture.workspaceID, repository, func(_ *sql.Tx, _ string) error { return nil }); !errors.Is(err, repositories.ErrNPMWriteTokenUnavailable) {
		_ = recoveredDB.Close()
		t.Fatalf("recovered NPM write credential remained usable: %v", err)
	}
	restored, err := storage.NewFileSystem(filepath.Join(parent, "restored", "object-store"))
	if err != nil {
		t.Fatal(err)
	}
	recoveredReceiver, err := npm.NewReceiptService(recoveredDB, recoveredRepositories, config.SQLite, restored, npm.ReceiptOptions{StagingDirectory: receiptStage, MaxConcurrent: 1, Limits: npm.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	if reader, _, err := recoveredReceiver.OpenPublishedArchiveWithToken(ctx, readToken.Bearer, fixture.workspaceID, repository, "fixture", "1.0.0"); !errors.Is(err, repositories.ErrPersonalTokenUnavailable) || reader != nil {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("recovered npm accepted original read token: %v", err)
	}
	newReadToken, err := recoveredRepositories.IssuePersonalReadToken(ctx, user, fixture.workspaceID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reader, size, err := recoveredReceiver.OpenPublishedArchiveWithToken(ctx, newReadToken.Bearer, fixture.workspaceID, repository, "fixture", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	recoveredBytes, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || size != int64(len(data)) || !bytes.Equal(recoveredBytes, data) {
		t.Fatalf("authorized recovered npm object differs: read=%v close=%v", readErr, closeErr)
	}
	if reader, _, err := recoveredReceiver.OpenPublishedArchiveWithToken(ctx, newReadToken.Bearer, fixture.workspaceID, fixture.repositoryID, "fixture", "1.0.0"); err == nil || reader != nil {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("recovered npm read crossed repository boundary: %v", err)
	}
	if _, err := fixture.repositoryService.VerifyPersonalReadToken(ctx, readToken.Bearer, fixture.workspaceID, repository); err != nil {
		t.Fatalf("isolated recovery changed source read token: %v", err)
	}
	if err := recoveredDB.Close(); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := backup.CopyGenericObject(ctx, restored, npmTrust.Inventory[0], &got); err != nil || !bytes.Equal(got.Bytes(), data) {
		t.Fatalf("restored NPM object: %v", err)
	}
	got.Reset()
	if err := backup.CopyGenericObject(ctx, source, npmTrust.Inventory[0], &got); err != nil || !bytes.Equal(got.Bytes(), data) {
		t.Fatalf("source NPM object changed during recovery: %v", err)
	}
}
