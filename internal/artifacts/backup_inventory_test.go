package artifacts

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"private-registry/internal/backup"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/spikes/sqlitebackup"
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
	if err := backup.CopyGenericObject(ctx, fixture.storage, objects[0], &copied); err != nil || !bytes.Equal(copied.Bytes(), before) {
		t.Fatalf("copy object from snapshot inventory: %v", err)
	}
	var liveCount int
	if err := fixture.db.QueryRowContext(ctx, `SELECT count(*) FROM registry_generic_upload_sessions WHERE status = 'uploaded'`).Scan(&liveCount); err != nil || liveCount != 2 {
		t.Fatalf("live synthetic state count=%d err=%v; want 2", liveCount, err)
	}
}
