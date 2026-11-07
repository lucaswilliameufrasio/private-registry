package artifacts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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
	"private-registry/internal/repositories"
	"private-registry/internal/spikes/sqlitebackup"
	"private-registry/internal/storage"
)

type syntheticRecoveryStage struct{ *os.File }

func (s syntheticRecoveryStage) Close() error {
	name := s.Name()
	if err := s.File.Close(); err != nil {
		return err
	}
	return os.Remove(name)
}

func TestGenericBackupInventoryIncludesPublishedAndPendingObjects(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	actor := fixture.userIDs["publisher"]
	content := []byte("synthetic shared content")
	first := startFixtureUpload(t, fixture, actor, "inventory", "v1", "one", content)
	if _, err := fixture.service.ReceiveUpload(ctx, actor, fixture.workspaceID, fixture.repositoryID, first.ID, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Publish(ctx, actor, fixture.workspaceID, fixture.repositoryID, first.ArtifactVersionID); err != nil {
		t.Fatal(err)
	}
	second := startFixtureUpload(t, fixture, actor, "inventory", "v2", "two", []byte("pending"))
	if _, err := fixture.service.ReceiveUpload(ctx, actor, fixture.workspaceID, fixture.repositoryID, second.ID, bytes.NewReader([]byte("pending"))); err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	objects, err := backup.InventoryGeneric(ctx, tx, 2, 3)
	if err != nil || len(objects) != 2 {
		t.Fatalf("generic inventory count=%d error=%v; want two distinct objects", len(objects), err)
	}
	if _, err := backup.InventoryGeneric(ctx, tx, 1, 3); err == nil {
		t.Fatal("inventory exceeded its bound without an error")
	}
	if _, err := backup.InventoryGeneric(ctx, tx, 2, 2); err == nil {
		t.Fatal("duplicate references exceeded their bound without an error")
	}
	if _, err := backup.InventoryGeneric(context.Background(), tx, 2, 3); err == nil {
		t.Fatal("inventory without a deadline was accepted")
	}
	for _, object := range objects {
		var copied bytes.Buffer
		if err := backup.CopyGenericObject(ctx, fixture.storage, object, &copied); err != nil || int64(copied.Len()) != object.Size {
			t.Fatalf("copy inventoried object length=%d err=%v", copied.Len(), err)
		}
		reader, info, err := fixture.storage.Open(ctx, object.Key)
		if err != nil {
			t.Fatal("open inventoried object:", err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		if info.Size != object.Size {
			t.Fatal("inventoried size does not match object")
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE registry_generic_upload_sessions SET status = 'rejected', object_size = 1 WHERE upload_session_id = ?`, first.ID); err != nil {
		t.Fatal("inject inconsistent synthetic reference:", err)
	}
	if _, err := backup.InventoryGeneric(ctx, tx, 2, 3); err == nil {
		t.Fatal("conflicting object sizes were accepted")
	}
}

func TestSQLiteSnapshotInventoryCopiesOnlySnapshotObjects(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	actor := fixture.userIDs["publisher"]
	before := []byte("synthetic before snapshot")
	first := startFixtureUpload(t, fixture, actor, "snapshot", "v1", "first", before)
	if _, err := fixture.service.ReceiveUpload(ctx, actor, fixture.workspaceID, fixture.repositoryID, first.ID, bytes.NewReader(before)); err != nil {
		t.Fatal(err)
	}
	version, err := fixture.service.Publish(ctx, actor, fixture.workspaceID, fixture.repositoryID, first.ArtifactVersionID)
	if err != nil || len(version.Files) != 1 {
		t.Fatalf("publish synthetic snapshot object: %v", err)
	}
	snapshotDir := filepath.Join(t.TempDir(), "snapshot")
	if err := os.Mkdir(snapshotDir, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(snapshotDir, "registry.sqlite")
	if _, err := sqlitebackup.Snapshot(ctx, fixture.db, snapshotPath, sqlitebackup.Options{PagesPerStep: 16}); err != nil {
		t.Fatal("create synthetic online snapshot:", err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	wrongIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ciphertextPath := filepath.Join(snapshotDir, "snapshot.age")
	if err := sqlitebackup.Encrypt(ctx, snapshotPath, ciphertextPath, identity.Recipient()); err != nil {
		t.Fatal("encrypt synthetic snapshot:", err)
	}
	recoveryDir := filepath.Join(t.TempDir(), "recovery")
	if err := os.Mkdir(recoveryDir, 0o700); err != nil {
		t.Fatal(err)
	}
	failedPath := filepath.Join(recoveryDir, "wrong-key.sqlite")
	if err := sqlitebackup.Decrypt(ctx, ciphertextPath, failedPath, wrongIdentity); err == nil {
		t.Fatal("incorrect recovery key decrypted snapshot")
	}
	if _, err := os.Stat(failedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed snapshot recovery left output: %v", err)
	}
	recoveredPath := filepath.Join(recoveryDir, "registry.sqlite")
	if err := sqlitebackup.Decrypt(ctx, ciphertextPath, recoveredPath, identity); err != nil {
		t.Fatal("recover synthetic snapshot:", err)
	}
	digestSnapshot := func(path string) (string, int64) {
		t.Helper()
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		digest, size, digestErr := backup.DigestSnapshot(ctx, file, 64<<20)
		closeErr := file.Close()
		if digestErr != nil || closeErr != nil {
			t.Fatalf("digest synthetic snapshot: digest=%v close=%v", digestErr, closeErr)
		}
		return digest, size
	}
	originalDigest, originalSize := digestSnapshot(snapshotPath)
	recoveredDigest, recoveredSize := digestSnapshot(recoveredPath)
	if originalDigest != recoveredDigest || originalSize != recoveredSize {
		t.Fatal("recovered snapshot digest or size differs")
	}
	after := []byte("synthetic after snapshot")
	second := startFixtureUpload(t, fixture, actor, "snapshot", "v2", "second", after)
	if _, err := fixture.service.ReceiveUpload(ctx, actor, fixture.workspaceID, fixture.repositoryID, second.ID, bytes.NewReader(after)); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: recoveryDir, DatabaseDriver: config.SQLite, DatabaseDSN: recoveredPath, DatabaseMaxOpenConns: 1}
	snapshotDB, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal("open isolated snapshot:", err)
	}
	t.Cleanup(func() { _ = snapshotDB.Close() })
	tx, err := snapshotDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	objects, err := backup.InventoryGeneric(ctx, tx, 10, 10)
	if err != nil || len(objects) != 1 {
		t.Fatalf("snapshot inventory count=%d err=%v; want one", len(objects), err)
	}
	var copied bytes.Buffer
	if err := backup.EncryptGenericObject(ctx, fixture.storage, objects[0], &copied, identity.Recipient()); err != nil {
		t.Fatalf("encrypt object from snapshot inventory: %v", err)
	}
	publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cipherDigest := sha256.Sum256(copied.Bytes())
	installationID, backupID := uuid.NewString(), uuid.NewString()
	receipt := backup.ObjectReceipt{Version: 1, InstallationID: installationID, BackupID: backupID, WorkspaceID: objects[0].Key.WorkspaceID, PlainSHA256: objects[0].Key.SHA256, PlainBytes: objects[0].Size, CipherSHA256: hex.EncodeToString(cipherDigest[:]), CipherBytes: int64(copied.Len())}
	envelope, err := backup.SignObjectReceipt(receipt, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	verifiedReceipt, err := backup.VerifyObjectReceipt(envelope, publicKey, installationID, backupID)
	if err != nil || verifiedReceipt != receipt {
		t.Fatalf("verify synthetic object receipt: %v", err)
	}
	verifiedObjects, err := backup.VerifyGenericReceipts(objects, []backup.ObjectReceiptEnvelope{envelope}, publicKey, installationID, backupID, 10)
	if err != nil || len(verifiedObjects) != 1 {
		t.Fatalf("verify synthetic inventory receipts: %v", err)
	}
	set := backup.GenericSet{Version: 1, InstallationID: installationID, BackupID: backupID, SnapshotSHA256: originalDigest, Objects: []backup.ObjectReceipt{receipt}}
	setEnvelope, err := backup.SignGenericSet(set, signingKey)
	if err != nil {
		t.Fatal("sign synthetic generic set:", err)
	}
	if _, err := backup.VerifyGenericSetInventory(setEnvelope, publicKey, installationID, backupID, recoveredDigest, objects); err != nil {
		t.Fatal("verify synthetic snapshot and object inventory:", err)
	}
	if _, err := age.Decrypt(bytes.NewReader(copied.Bytes()), wrongIdentity); err == nil {
		t.Fatal("incorrect recovery identity decrypted synthetic object")
	}
	truncated, err := age.Decrypt(bytes.NewReader(copied.Bytes()[:copied.Len()-1]), identity)
	if err == nil {
		if _, err := io.Copy(io.Discard, truncated); err == nil {
			t.Fatal("truncated ciphertext was accepted")
		}
	}
	var recovered bytes.Buffer
	err = backup.DecryptGenericObject(ctx, bytes.NewReader(copied.Bytes()), int64(copied.Len()), objects[0], &recovered, identity)
	recoveredBytes := recovered.Bytes()
	if err != nil || !bytes.Equal(recoveredBytes, before) {
		t.Fatalf("verify synthetic recovery identity: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal("close snapshot inventory transaction:", err)
	}
	restoredStore, err := storage.NewFileSystem(filepath.Join(t.TempDir(), "restored-objects"))
	if err != nil {
		t.Fatal(err)
	}
	stagingDir := t.TempDir()
	newStage := func() (backup.RecoveryStage, error) {
		file, err := os.CreateTemp(stagingDir, "synthetic-stage-*")
		if err != nil {
			return nil, err
		}
		return syntheticRecoveryStage{File: file}, nil
	}
	trusted := backup.GenericSetRecovery{Signer: publicKey, InstallationID: installationID, BackupID: backupID, SnapshotSHA256: recoveredDigest, Inventory: objects}
	sources := []backup.RecoveryObjectSource{{Receipt: envelope, Open: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(copied.Bytes())), nil
	}}}
	if err := backup.RestoreGenericSet(ctx, setEnvelope, trusted, sources, identity, newStage, restoredStore); err != nil {
		t.Fatalf("restore synthetic object: %v", err)
	}
	archiveStore, err := storage.NewFileSystem(filepath.Join(t.TempDir(), "captured-objects"))
	if err != nil {
		t.Fatal(err)
	}
	captured, err := backup.CaptureGenericSet(ctx, trusted, fixture.storage, archiveStore, identity.Recipient(), signingKey, 4096, newStage)
	if err != nil || len(captured.Receipts) != 1 {
		t.Fatalf("capture generic snapshot inventory receipts=%d error=%v", len(captured.Receipts), err)
	}
	capturedReceipt, err := backup.VerifyObjectReceipt(captured.Receipts[0], publicKey, installationID, backupID)
	if err != nil {
		t.Fatal(err)
	}
	capturedKey := storage.ObjectKey{WorkspaceID: capturedReceipt.WorkspaceID, SHA256: capturedReceipt.CipherSHA256}
	capturedSources := []backup.RecoveryObjectSource{{Receipt: captured.Receipts[0], Open: func(ctx context.Context) (io.ReadCloser, error) {
		reader, _, err := archiveStore.Open(ctx, capturedKey)
		return reader, err
	}}}
	capturedRestore, err := storage.NewFileSystem(filepath.Join(t.TempDir(), "captured-restore"))
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.RestoreGenericSet(ctx, captured.Set, trusted, capturedSources, identity, newStage, capturedRestore); err != nil {
		t.Fatal("recover captured snapshot inventory:", err)
	}
	var capturedBytes bytes.Buffer
	if err := backup.CopyGenericObject(ctx, capturedRestore, objects[0], &capturedBytes); err != nil || !bytes.Equal(capturedBytes.Bytes(), before) {
		t.Fatalf("verify captured snapshot inventory bytes: %v", err)
	}
	restoredRepositories, err := repositories.New(snapshotDB, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	restoredService, err := New(snapshotDB, config.SQLite, restoredRepositories, restoredStore, Options{MaxUploadBytes: 1024, MaxConcurrentUploads: 1})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := restoredService.OpenFile(ctx, fixture.userIDs["reader"], fixture.workspaceID, fixture.repositoryID, version.Files[0].ID, 0, int64(len(before)))
	if err != nil {
		t.Fatal("read restored synthetic content:", err)
	}
	restoredBytes, readErr := io.ReadAll(opened.Reader)
	closeErr := opened.Reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(restoredBytes, before) {
		t.Fatalf("restored synthetic content read=%v close=%v", readErr, closeErr)
	}
	if _, err := restoredService.OpenFile(ctx, fixture.userIDs["member"], fixture.workspaceID, fixture.repositoryID, version.Files[0].ID, 0, int64(len(before))); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("ungranted restored content read = %v", err)
	}
	var liveCount int
	if err := fixture.db.QueryRowContext(ctx, `SELECT count(*) FROM registry_generic_upload_sessions WHERE status IN ('uploaded', 'published')`).Scan(&liveCount); err != nil || liveCount != 2 {
		t.Fatalf("live synthetic state count=%d err=%v; want 2", liveCount, err)
	}
}
