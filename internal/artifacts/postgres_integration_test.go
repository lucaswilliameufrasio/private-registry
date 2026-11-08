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
	"private-registry/internal/backup"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/jobs"
	"private-registry/internal/migrations"
	"private-registry/internal/repositories"
	"private-registry/internal/sessions"
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
	exerciseNPMReceiptValidatesAndStores(t, db, config.Postgres, repositoryService, objectStore, workspaceID, ownerID, publisherID)

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
	snapshot, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("begin PostgreSQL inventory snapshot:", err)
	}
	objects, inventoryErr := backup.InventoryGeneric(ctx, snapshot, 1, 2)
	rollbackErr := snapshot.Rollback()
	if inventoryErr != nil || rollbackErr != nil || len(objects) != 1 || objects[0].Size != int64(len(payload)) {
		t.Fatalf("PostgreSQL inventory count=%d inventory error=%v rollback error=%v", len(objects), inventoryErr, rollbackErr)
	}
	var copied bytes.Buffer
	if err := backup.CopyGenericObject(ctx, objectStore, objects[0], &copied); err != nil || !bytes.Equal(copied.Bytes(), payload) {
		t.Fatalf("copy PostgreSQL-inventoried object: %v", err)
	}
	if _, err := service.ResolvePublicFile(ctx, "artifact-postgres", "artifacts", "postgres-release", "build-42", "dist/package.tar"); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("private PostgreSQL public resolution = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET visibility = 'unlisted' WHERE repository_id = $1`, repositoryID); err != nil {
		t.Fatal(err)
	}
	publicFile, err := service.ResolvePublicFile(ctx, "artifact-postgres", "artifacts", "postgres-release", "build-42", "dist/package.tar")
	if err != nil {
		t.Fatal("resolve PostgreSQL public file:", err)
	}
	publicStream, err := service.OpenPublicFile(ctx, "artifact-postgres", "artifacts", "postgres-release", "build-42", publicFile.Path, publicFile.ID, 0, publicFile.Size)
	if err != nil {
		t.Fatal("open PostgreSQL public file:", err)
	}
	publicBytes, readErr := io.ReadAll(publicStream.Reader)
	closeErr := publicStream.Reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(publicBytes, payload) {
		t.Fatalf("PostgreSQL public read=%v close=%v", readErr, closeErr)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_generic_artifact_versions SET status = 'quarantined' WHERE artifact_version_id = $1`, version.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ResolvePublicFile(ctx, "artifact-postgres", "artifacts", "postgres-release", "build-42", publicFile.Path); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("quarantined public resolution = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_generic_artifact_versions SET status = 'published' WHERE artifact_version_id = $1`, version.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET visibility = 'private' WHERE repository_id = $1`, repositoryID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.OpenPublicFile(ctx, "artifact-postgres", "artifacts", "postgres-release", "build-42", publicFile.Path, publicFile.ID, 0, publicFile.Size); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("PostgreSQL open after privatization = %v", err)
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
	postgresSessions, err := sessions.New(db, config.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	oldSession, err := postgresSessions.Create(ctx, readerID, sessions.LevelStandard)
	if err != nil {
		t.Fatal(err)
	}
	oldToken, err := repositoryService.IssuePersonalReadToken(ctx, readerID, workspaceID, repositoryID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := jobs.New(db, config.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	jobNow := time.Now().UTC()
	if _, err := queue.Enqueue(ctx, "synthetic-recovery-running", "synthetic-recovery", "{}", 3, jobNow, jobNow); err != nil {
		t.Fatal(err)
	}
	job, err := queue.Claim(ctx, "synthetic-recovery", jobNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Enqueue(ctx, "synthetic-recovery-pending", "synthetic-recovery", "{}", 3, jobNow, jobNow); err != nil {
		t.Fatal(err)
	}
	recoveryUpload, err := service.StartUpload(ctx, publisherID, workspaceID, repositoryID, requestFor("recovery-uploaded", "v1", "file", payload))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReceiveUpload(ctx, publisherID, workspaceID, repositoryID, recoveryUpload.ID, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	receivingUpload, err := service.StartUpload(ctx, publisherID, workspaceID, repositoryID, requestFor("recovery-receiving", "v1", "file", payload))
	if err != nil {
		t.Fatal(err)
	}
	recoveryTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	invalidated, err := backup.InvalidateRestoredCredentials(ctx, recoveryTx, config.Postgres, time.Now())
	if err != nil || invalidated.Sessions != 1 || invalidated.PersonalTokens != 3 || invalidated.DownloadTickets != 1 {
		_ = recoveryTx.Rollback()
		t.Fatalf("PostgreSQL recovery invalidation counts=%+v error=%v", invalidated, err)
	}
	repeated, err := backup.InvalidateRestoredCredentials(ctx, recoveryTx, config.Postgres, time.Now())
	if err != nil || repeated != (backup.InvalidatedCredentials{}) {
		_ = recoveryTx.Rollback()
		t.Fatalf("repeated PostgreSQL invalidation counts=%+v error=%v", repeated, err)
	}
	held, err := backup.HoldRestoredJobs(ctx, recoveryTx, config.Postgres, jobNow)
	if err != nil || held != 2 {
		_ = recoveryTx.Rollback()
		t.Fatalf("PostgreSQL recovery held jobs=%d error=%v", held, err)
	}
	heldAgain, err := backup.HoldRestoredJobs(ctx, recoveryTx, config.Postgres, jobNow)
	if err != nil || heldAgain != 0 {
		_ = recoveryTx.Rollback()
		t.Fatalf("repeated PostgreSQL recovery held jobs=%d error=%v", heldAgain, err)
	}
	uploads, err := backup.InvalidateRestoredUploads(ctx, recoveryTx, config.Postgres, jobNow)
	if err != nil || uploads != 6 {
		_ = recoveryTx.Rollback()
		t.Fatalf("PostgreSQL recovery invalidated uploads=%d error=%v", uploads, err)
	}
	var npmStatus string
	var npmInvalidated int
	if err := recoveryTx.QueryRowContext(ctx, `SELECT r.status, r.recovery_invalidated FROM registry_npm_reservations r JOIN registry_repositories p ON p.repository_id = r.repository_id WHERE r.workspace_id = $1 AND p.slug = 'npm-receive' AND r.name = 'fixture' AND r.object_verified = 1`, workspaceID).Scan(&npmStatus, &npmInvalidated); err != nil || npmStatus != "uploaded" || npmInvalidated != 1 {
		_ = recoveryTx.Rollback()
		t.Fatalf("PostgreSQL recovery did not hold npm receipt: status=%q invalidated=%d err=%v", npmStatus, npmInvalidated, err)
	}
	if err := recoveryTx.QueryRowContext(ctx, `SELECT status, recovery_invalidated FROM registry_npm_reservations WHERE workspace_id = $1 AND name = 'fixture' AND object_verified = 0`, workspaceID).Scan(&npmStatus, &npmInvalidated); err != nil || npmStatus != "expired" || npmInvalidated != 1 {
		_ = recoveryTx.Rollback()
		t.Fatalf("PostgreSQL recovery did not expire npm reservation: status=%q invalidated=%d err=%v", npmStatus, npmInvalidated, err)
	}
	var publishedCount, remainingCount int
	if err := recoveryTx.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_npm_reservations r JOIN registry_npm_publications p ON p.reservation_id = r.reservation_id WHERE r.workspace_id = $1 AND r.status = 'uploaded' AND r.recovery_invalidated = 1`, workspaceID).Scan(&publishedCount); err != nil || publishedCount != 1 {
		_ = recoveryTx.Rollback()
		t.Fatalf("PostgreSQL recovery did not hold published npm receipt: count=%d err=%v", publishedCount, err)
	}
	if err := recoveryTx.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_npm_reservations WHERE workspace_id = $1 AND name = 'remaining' AND status = 'expired' AND recovery_invalidated = 1`, workspaceID).Scan(&remainingCount); err != nil || remainingCount != 1 {
		_ = recoveryTx.Rollback()
		t.Fatalf("PostgreSQL recovery did not expire remaining npm reservation: count=%d err=%v", remainingCount, err)
	}
	uploadsAgain, err := backup.InvalidateRestoredUploads(ctx, recoveryTx, config.Postgres, jobNow)
	if err != nil || uploadsAgain != 0 {
		_ = recoveryTx.Rollback()
		t.Fatalf("repeated PostgreSQL recovery invalidated uploads=%d error=%v", uploadsAgain, err)
	}
	var receivedStatus, uploadedStatus string
	var uploadInvalidated int
	if err := recoveryTx.QueryRowContext(ctx, `SELECT status FROM registry_generic_upload_sessions WHERE upload_session_id = $1`, receivingUpload.ID).Scan(&receivedStatus); err != nil || receivedStatus != "expired" {
		_ = recoveryTx.Rollback()
		t.Fatalf("PostgreSQL recovered receiving status=%s error=%v", receivedStatus, err)
	}
	if err := recoveryTx.QueryRowContext(ctx, `SELECT status, recovery_invalidated FROM registry_generic_upload_sessions WHERE upload_session_id = $1`, recoveryUpload.ID).Scan(&uploadedStatus, &uploadInvalidated); err != nil || uploadedStatus != "uploaded" || uploadInvalidated != 1 {
		_ = recoveryTx.Rollback()
		t.Fatalf("PostgreSQL recovered uploaded status=%s invalidated=%d error=%v", uploadedStatus, uploadInvalidated, err)
	}
	if err := recoveryTx.Rollback(); err != nil {
		t.Fatal("roll back isolated PostgreSQL recovery test:", err)
	}
	if err := queue.Heartbeat(ctx, job.ID, job.LeaseToken, jobNow.Add(time.Second), time.Hour); err != nil {
		t.Fatal("source job lease changed after rolled back recovery:", err)
	}
	if _, err := service.Publish(ctx, publisherID, workspaceID, repositoryID, recoveryUpload.ArtifactVersionID); err != nil {
		t.Fatal("source upload changed after rolled back recovery:", err)
	}
	if _, err := postgresSessions.Validate(ctx, oldSession.BearerToken); err != nil {
		t.Fatal("source session changed after rolled back recovery:", err)
	}
	if _, err := repositoryService.VerifyPersonalReadToken(ctx, oldToken.Bearer, workspaceID, repositoryID); err != nil {
		t.Fatal("source token changed after rolled back recovery:", err)
	}
	if _, _, err := service.ResolveDownloadTicket(ctx, ticket.Token); err != nil {
		t.Fatal("source ticket changed after rolled back recovery:", err)
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
	if _, err := db.ExecContext(ctx, `UPDATE registry_generic_upload_sessions SET expires_at = $1 WHERE upload_session_id = $2`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), limitSession.ID); err != nil {
		t.Fatal("expire PostgreSQL upload:", err)
	}
	count, err := service.ExpireUploadBatch(ctx, time.Now().UTC(), 10)
	if err != nil || count != 1 {
		t.Fatalf("PostgreSQL expiration count = %d, error = %v; want 1", count, err)
	}
	count, err = service.ExpireUploadBatch(ctx, time.Now().UTC(), 10)
	if err != nil || count != 0 {
		t.Fatalf("repeated PostgreSQL expiration count = %d, error = %v; want 0", count, err)
	}
	quotaWorkspace, quotaRepository := uuid.NewString(), uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspaces (workspace_id, slug, display_name, status, created_by, created_at) VALUES ($1, 'quota-postgres', 'Quota', 'active', $2, $3)`, quotaWorkspace, ownerID, now); err != nil {
		t.Fatal("seed quota workspace:", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, status, created_by, created_at, updated_at) VALUES ($1, $2, 'member', 'active', $3, $4, $4)`, quotaWorkspace, publisherID, ownerID, now); err != nil {
		t.Fatal("seed quota membership:", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, visibility, status, created_by, created_at, updated_at) VALUES ($1, $2, 'quota', 'Quota', 'private', 'active', $3, $4, $4)`, quotaRepository, quotaWorkspace, ownerID, now); err != nil {
		t.Fatal("seed quota repository:", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES ($1, $2, $3, $4, 'publisher', $5, $6)`, uuid.NewString(), quotaRepository, quotaWorkspace, publisherID, ownerID, now); err != nil {
		t.Fatal("seed quota grant:", err)
	}
	exerciseGenericQuota(t, service, db, config.Postgres, publisherID, quotaWorkspace, quotaRepository)
	crossWorkspace, crossRepository := uuid.NewString(), uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspaces (workspace_id, slug, display_name, status, created_by, created_at) VALUES ($1, 'cargo-cross-quota', 'Cross quota', 'active', $2, $3)`, crossWorkspace, ownerID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, status, created_by, created_at, updated_at) VALUES ($1, $2, 'member', 'active', $3, $4, $4)`, crossWorkspace, publisherID, ownerID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at) VALUES ($1, $2, 'generic', 'Generic', $3, $4, $4)`, crossRepository, crossWorkspace, ownerID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES ($1, $2, $3, $4, 'publisher', $5, $6)`, uuid.NewString(), crossRepository, crossWorkspace, publisherID, ownerID, now); err != nil {
		t.Fatal(err)
	}
	exerciseGenericQuotaCountsCargo(t, service, db, config.Postgres, publisherID, crossWorkspace, crossRepository)
	npmWorkspace, npmGenericRepository := uuid.NewString(), uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspaces (workspace_id, slug, display_name, status, created_by, created_at) VALUES ($1, 'npm-cross-quota', 'npm quota', 'active', $2, $3)`, npmWorkspace, ownerID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, status, created_by, created_at, updated_at) VALUES ($1, $2, 'member', 'active', $3, $4, $4)`, npmWorkspace, publisherID, ownerID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at) VALUES ($1, $2, 'generic', 'Generic', $3, $4, $4)`, npmGenericRepository, npmWorkspace, ownerID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES ($1, $2, $3, $4, 'publisher', $5, $6)`, uuid.NewString(), npmGenericRepository, npmWorkspace, publisherID, ownerID, now); err != nil {
		t.Fatal(err)
	}
	exerciseGenericQuotaCountsNPM(t, service, db, config.Postgres, publisherID, npmWorkspace, npmGenericRepository)
	reservationWorkspace, reservationRepository := uuid.NewString(), uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspaces (workspace_id, slug, display_name, status, created_by, created_at) VALUES ($1, 'npm-reservation-quota', 'npm reservation', 'active', $2, $3)`, reservationWorkspace, ownerID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, status, created_by, created_at, updated_at) VALUES ($1, $2, 'owner', 'active', $2, $3, $3)`, reservationWorkspace, ownerID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, status, created_by, created_at, updated_at) VALUES ($1, $2, 'member', 'active', $3, $4, $4)`, reservationWorkspace, publisherID, ownerID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at) VALUES ($1, $2, 'generic', 'Generic', $3, $4, $4)`, reservationRepository, reservationWorkspace, ownerID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES ($1, $2, $3, $4, 'publisher', $5, $6)`, uuid.NewString(), reservationRepository, reservationWorkspace, publisherID, ownerID, now); err != nil {
		t.Fatal(err)
	}
	exerciseNPMReservationQuotaAndLifecycle(t, service, db, config.Postgres, publisherID, reservationWorkspace, reservationRepository)
}
