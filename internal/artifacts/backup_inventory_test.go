package artifacts

import (
	"bytes"
	"context"
	"testing"

	"private-registry/internal/backup"
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
