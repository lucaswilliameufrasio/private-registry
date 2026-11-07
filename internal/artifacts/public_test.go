package artifacts

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestPublicFileRequiresPublishedVisibleRepository(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx := context.Background()
	actor := fixture.userIDs["publisher"]
	payload := []byte("synthetic public script")
	session := startFixtureUpload(t, fixture, actor, "widget", "v1", "dist/widget.js", payload)
	if _, err := fixture.service.ReceiveUpload(ctx, actor, fixture.workspaceID, fixture.repositoryID, session.ID, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Publish(ctx, actor, fixture.workspaceID, fixture.repositoryID, session.ArtifactVersionID); err != nil {
		t.Fatal(err)
	}
	resolve := func() (File, error) {
		return fixture.service.ResolvePublicFile(ctx, "artifact-workspace", "artifacts", "widget", "v1", "dist/widget.js")
	}
	before := fixture.storage.opens.Load()
	if _, err := resolve(); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("private public resolution = %v", err)
	}
	if _, err := fixture.service.OpenPublicFile(ctx, "artifact-workspace", "artifacts", "widget", "v1", "dist/widget.js", "irrelevant", 0, int64(len(payload))); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("private public open = %v", err)
	}
	if fixture.storage.opens.Load() != before {
		t.Fatal("private public request touched storage")
	}
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_repositories SET visibility = 'unlisted' WHERE repository_id = ?`, fixture.repositoryID); err != nil {
		t.Fatal(err)
	}
	startFixtureUpload(t, fixture, actor, "widget", "v2", "dist/widget.js", payload)
	if _, err := fixture.service.ResolvePublicFile(ctx, "artifact-workspace", "artifacts", "widget", "v2", "dist/widget.js"); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("unpublished public resolution = %v", err)
	}
	file, err := resolve()
	if err != nil {
		t.Fatal("resolve public file:", err)
	}
	opened, err := fixture.service.OpenPublicFile(ctx, "artifact-workspace", "artifacts", "widget", "v1", file.Path, file.ID, 0, file.Size)
	if err != nil {
		t.Fatal("open public file:", err)
	}
	content, readErr := io.ReadAll(opened.Reader)
	closeErr := opened.Reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(content, payload) {
		t.Fatalf("public content read=%v close=%v", readErr, closeErr)
	}
	if _, err := fixture.service.ResolvePublicFile(ctx, "artifact-workspace", "artifacts", "widget", "v1", "../widget.js"); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("traversal resolution = %v", err)
	}
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_repositories SET visibility = 'private' WHERE repository_id = ?`, fixture.repositoryID); err != nil {
		t.Fatal(err)
	}
	before = fixture.storage.opens.Load()
	if _, err := fixture.service.OpenPublicFile(ctx, "artifact-workspace", "artifacts", "widget", "v1", file.Path, file.ID, 0, file.Size); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("public open after visibility change = %v", err)
	}
	if fixture.storage.opens.Load() != before {
		t.Fatal("visibility recheck occurred after storage access")
	}
}
