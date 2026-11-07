package artifacts

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"private-registry/internal/backup"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/repositories"
	"private-registry/internal/spikes/sqlitebackup"
	"private-registry/internal/storage"
)

func TestGenericBackupInventoryIncludesPublishedAndPendingObjects(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx := context.Background()
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
	objects, err := backup.InventoryGeneric(ctx, tx, 2)
	if err != nil || len(objects) != 2 {
		t.Fatalf("generic inventory count=%d error=%v; want two distinct objects", len(objects), err)
	}
	if _, err := backup.InventoryGeneric(ctx, tx, 1); err == nil {
		t.Fatal("inventory exceeded its bound without an error")
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
	if _, err := backup.InventoryGeneric(ctx, tx, 2); err == nil {
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
	after := []byte("synthetic after snapshot")
	second := startFixtureUpload(t, fixture, actor, "snapshot", "v2", "second", after)
	if _, err := fixture.service.ReceiveUpload(ctx, actor, fixture.workspaceID, fixture.repositoryID, second.ID, bytes.NewReader(after)); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: snapshotDir, DatabaseDriver: config.SQLite, DatabaseDSN: snapshotPath, DatabaseMaxOpenConns: 1}
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
	objects, err := backup.InventoryGeneric(ctx, tx, 10)
	if err != nil || len(objects) != 1 {
		t.Fatalf("snapshot inventory count=%d err=%v; want one", len(objects), err)
	}
	var copied bytes.Buffer
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := age.Encrypt(&copied, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.CopyGenericObject(ctx, fixture.storage, objects[0], encrypted); err != nil {
		t.Fatalf("encrypt object from snapshot inventory: %v", err)
	}
	if err := encrypted.Close(); err != nil {
		t.Fatal("complete synthetic ciphertext:", err)
	}
	wrongIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
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
	decrypted, err := age.Decrypt(bytes.NewReader(copied.Bytes()), identity)
	if err != nil {
		t.Fatal("decrypt synthetic object:", err)
	}
	recoveredBytes, err := io.ReadAll(decrypted)
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
	restored, err := restoredStore.Put(ctx, objects[0].Key.WorkspaceID, bytes.NewReader(recoveredBytes), objects[0].Size)
	if err != nil || restored.Key != objects[0].Key || restored.Size != objects[0].Size {
		t.Fatalf("restore synthetic object: %v", err)
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
