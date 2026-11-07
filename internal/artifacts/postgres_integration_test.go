//go:build integration

package artifacts

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
	"private-registry/internal/testinfra"
)

func TestPostgresGenericArtifactPublishAndTicketedDownload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	postgres, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal("start isolated PostgreSQL:", err)
	}
	t.Cleanup(func() {
		if err := postgres.Stop(); err != nil {
			t.Errorf("stop owned PostgreSQL fixture: %v", err)
		}
	})

	cfg := config.Config{
		DatabaseDriver:       config.Postgres,
		DatabaseDSN:          postgres.DSN(),
		DatabaseMaxOpenConns: 8,
	}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal("open PostgreSQL:", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close PostgreSQL: %v", err)
		}
	})
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal("apply PostgreSQL migrations:", err)
	}

	ownerID := uuid.NewString()
	publisherID := uuid.NewString()
	readerID := uuid.NewString()
	workspaceID := uuid.NewString()
	repositoryID := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, user := range []struct {
		id   string
		name string
	}{{ownerID, "PostgreSQL Artifact Owner"}, {publisherID, "PostgreSQL Artifact Publisher"}, {readerID, "PostgreSQL Artifact Reader"}} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO registry_users
				(user_id, display_name, email, email_verified, status, created_at, updated_at)
			 VALUES ($1, $2, NULL, FALSE, 'active', $3, $3)`, user.id, user.name, now); err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO registry_workspaces (workspace_id, slug, display_name, status, created_by, created_at)
		 VALUES ($1, 'artifact-postgres', 'PostgreSQL Artifacts', 'active', $2, $3)`, workspaceID, ownerID, now); err != nil {
		t.Fatal("seed workspace:", err)
	}
	for _, member := range []struct {
		userID string
		role   string
	}{{ownerID, "owner"}, {publisherID, "member"}, {readerID, "member"}} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO registry_workspace_memberships
				(workspace_id, user_id, role, status, created_by, created_at, updated_at)
			 VALUES ($1, $2, $3, 'active', $4, $5, $5)`, workspaceID, member.userID, member.role, ownerID, now); err != nil {
			t.Fatalf("seed %s membership: %v", member.role, err)
		}
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO registry_repositories
			(repository_id, workspace_id, slug, display_name, visibility, status, created_by, created_at, updated_at)
		 VALUES ($1, $2, 'artifacts', 'Artifacts', 'private', 'active', $3, $4, $4)`,
		repositoryID, workspaceID, ownerID, now); err != nil {
		t.Fatal("seed repository:", err)
	}
	for _, grant := range []struct {
		userID string
		role   string
	}{{publisherID, "publisher"}, {readerID, "reader"}} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO registry_repository_grants
				(grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			uuid.NewString(), repositoryID, workspaceID, grant.userID, grant.role, ownerID, now); err != nil {
			t.Fatalf("seed %s grant: %v", grant.role, err)
		}
	}

	repositoryService, err := repositories.New(db, config.Postgres)
	if err != nil {
		t.Fatal("create repository service:", err)
	}
	objectStore, err := storage.NewFileSystem(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal("create filesystem object store:", err)
	}
	service, err := New(db, config.Postgres, repositoryService, objectStore, Options{
		MaxUploadBytes:       1 << 20,
		MaxConcurrentUploads: 2,
	})
	if err != nil {
		t.Fatal("create artifact service:", err)
	}

	payload := []byte("PostgreSQL publication and ticketed read")
	session, err := service.StartUpload(ctx, publisherID, workspaceID, repositoryID,
		requestFor("postgres-release", "build-42", "dist/package.tar", payload))
	if err != nil {
		t.Fatal("start PostgreSQL upload:", err)
	}
	blockedBody := &blockingReader{
		reader:  bytes.NewReader(payload),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	firstUpload := make(chan error, 1)
	go func() {
		_, err := service.ReceiveUpload(ctx, publisherID, workspaceID, repositoryID, session.ID, blockedBody)
		firstUpload <- err
	}()
	select {
	case <-blockedBody.started:
	case <-ctx.Done():
		close(blockedBody.release)
		t.Fatal("PostgreSQL upload body was not read before timeout")
	}
	concurrentBody := &countingReader{reader: bytes.NewReader(payload)}
	if _, err := service.ReceiveUpload(ctx, publisherID, workspaceID, repositoryID, session.ID,
		concurrentBody); !errors.Is(err, ErrUploadStateConflict) {
		close(blockedBody.release)
		t.Fatalf("concurrent PostgreSQL upload error = %v; want ErrUploadStateConflict", err)
	}
	if concurrentBody.bytesRead.Load() != 0 {
		close(blockedBody.release)
		t.Fatalf("concurrent PostgreSQL request consumed %d bytes; want no read", concurrentBody.bytesRead.Load())
	}
	close(blockedBody.release)
	select {
	case err := <-firstUpload:
		if err != nil {
			t.Fatal("receive PostgreSQL upload:", err)
		}
	case <-ctx.Done():
		t.Fatal("PostgreSQL upload did not complete before timeout")
	}
	version, err := service.Publish(ctx, publisherID, workspaceID, repositoryID, session.ArtifactVersionID)
	if err != nil {
		t.Fatal("publish PostgreSQL artifact:", err)
	}
	if version.Status != "published" || len(version.Files) != 1 {
		t.Fatalf("PostgreSQL published version = %+v", version)
	}

	ticket, err := service.IssueDownloadTicket(ctx, readerID, workspaceID, repositoryID,
		version.ID, version.Files[0].ID, 0)
	if err != nil {
		t.Fatal("issue PostgreSQL download ticket:", err)
	}
	opened, expiry, err := service.OpenDownloadTicket(ctx, ticket.Token, 7, 11)
	if err != nil {
		t.Fatal("open ranged PostgreSQL ticket:", err)
	}
	content, err := io.ReadAll(opened.Reader)
	if closeErr := opened.Reader.Close(); closeErr != nil {
		t.Fatal("close PostgreSQL ranged stream:", closeErr)
	}
	if err != nil || !opened.Range || !bytes.Equal(content, payload[7:18]) || !expiry.Equal(ticket.ExpiresAt) {
		t.Fatalf("PostgreSQL ticket range = %q range=%t expiry=%s err=%v", content, opened.Range, expiry, err)
	}
	var publicationAuditCount int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM registry_audit_events
		 WHERE actor_user_id = $1 AND action = 'artifact.generic.published' AND target_id = $2`,
		publisherID, version.ID).Scan(&publicationAuditCount); err != nil {
		t.Fatal("read PostgreSQL publication audit:", err)
	}
	if publicationAuditCount != 1 {
		t.Fatalf("PostgreSQL publication audit count = %d; want 1", publicationAuditCount)
	}

	limitSession, err := service.StartUpload(ctx, publisherID, workspaceID, repositoryID,
		requestFor("bounded", "v1", "first", payload))
	if err != nil {
		t.Fatal("start bounded PostgreSQL version:", err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO registry_generic_upload_sessions
		(upload_session_id, artifact_version_id, workspace_id, repository_id, path,
		 content_type, expected_size, expected_sha256, status, created_by, created_at, expires_at, updated_at)
	SELECT lpad(i::text, 36, '0'), artifact_version_id, workspace_id, repository_id, 'file-' || i::text,
		content_type, expected_size, expected_sha256, status, created_by, created_at, expires_at, updated_at
	FROM registry_generic_upload_sessions CROSS JOIN generate_series(1, $1::integer) AS i
	WHERE upload_session_id = $2`, MaxCollectionFiles-2, limitSession.ID)
	if err != nil {
		t.Fatal("populate PostgreSQL reservations:", err)
	}
	results := make(chan error, 2)
	for _, name := range []string{"last-a", "last-b"} {
		request := requestFor("bounded", "v1", name, payload)
		go func() {
			_, err := service.StartUpload(ctx, publisherID, workspaceID, repositoryID, request)
			results <- err
		}()
	}
	var successes, conflicts int
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrVersionConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent PostgreSQL reservation failed: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("PostgreSQL concurrent starts: %d successes and %d conflicts; want one of each", successes, conflicts)
	}
}
