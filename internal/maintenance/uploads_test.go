package maintenance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/artifacts"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/gomod"
	"private-registry/internal/jobs"
	"private-registry/internal/migrations"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

type blockingExpirer struct{ started chan struct{} }

func (b blockingExpirer) ExpireUploadBatch(ctx context.Context, _ time.Time, _ int) (int, error) {
	close(b.started)
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestUploadExpirationRunsAndSurvivesWorkerRestart(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	cfg := config.Config{DataDir: dataDir, DatabaseDriver: config.SQLite, DatabaseDSN: filepath.Join(dataDir, "registry.sqlite"), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	exerciseUploadExpiration(t, db, config.SQLite, root)
}

func exerciseUploadExpiration(t *testing.T, db *sql.DB, driver config.DatabaseDriver, root string) {
	t.Helper()
	ctx := context.Background()
	bind := func(query string) string {
		if driver != config.Postgres {
			return query
		}
		for index := 1; strings.Contains(query, "?"); index++ {
			query = strings.Replace(query, "?", fmt.Sprintf("$%d", index), 1)
		}
		return query
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	timestamp := now.Format(time.RFC3339Nano)
	userID, workspaceID, repositoryID, versionID, sessionID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, status, created_at, updated_at) VALUES (?, 'Synthetic', 'active', ?, ?)`, []any{userID, timestamp, timestamp}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, status, created_by, created_at) VALUES (?, 'synthetic', 'Synthetic', 'active', ?, ?)`, []any{workspaceID, userID, timestamp}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, visibility, status, created_by, created_at, updated_at) VALUES (?, ?, 'synthetic', 'Synthetic', 'private', 'active', ?, ?, ?)`, []any{repositoryID, workspaceID, userID, timestamp, timestamp}},
		{`INSERT INTO registry_generic_artifact_versions (artifact_version_id, workspace_id, repository_id, collection_name, version_label, status, created_by, created_at) VALUES (?, ?, ?, 'synthetic', 'v1', 'receiving', ?, ?)`, []any{versionID, workspaceID, repositoryID, userID, timestamp}},
		{`INSERT INTO registry_generic_upload_sessions (upload_session_id, artifact_version_id, workspace_id, repository_id, path, content_type, expected_size, expected_sha256, status, created_by, created_at, expires_at, updated_at) VALUES (?, ?, ?, ?, 'a', 'text/plain', 0, ?, 'receiving', ?, ?, ?, ?)`, []any{sessionID, versionID, workspaceID, repositoryID, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", userID, timestamp, now.Add(-time.Minute).Format(time.RFC3339Nano), timestamp}},
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, bind(statement.query), statement.args...); err != nil {
			t.Fatal("seed expiration fixture:", err)
		}
	}
	repositoryService, err := repositories.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := artifacts.New(db, driver, repositoryService, store, artifacts.Options{MaxUploadBytes: 1024, MaxConcurrentUploads: 1})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := jobs.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	goRepository := uuid.NewString()
	if _, err := db.ExecContext(ctx, bind(`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, visibility, status, created_by, created_at, updated_at, format) VALUES (?, ?, 'go-modules', 'Go', 'private', 'active', ?, ?, ?, 'go')`), goRepository, workspaceID, userID, timestamp, timestamp); err != nil {
		t.Fatal(err)
	}
	goIDs := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	for index, entry := range []struct {
		status   string
		claim    any
		verified int
		expires  time.Time
	}{
		{"receiving", nil, 0, now.Add(-time.Minute)},
		{"uploading", uuid.NewString(), 0, now.Add(-time.Minute)},
		{"uploaded", nil, 1, now.Add(-time.Minute)},
		{"receiving", nil, 0, now.Add(time.Hour)},
	} {
		query := `INSERT INTO registry_go_upload_sessions (upload_session_id, workspace_id, repository_id, module_path, version, mod_bytes, zip_sha256, zip_size, source_time, status, upload_claim_id, object_verified, created_by, created_at_ms, expires_at_ms) VALUES (?, ?, ?, 'example.com/private/module', ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)`
		if _, err := db.ExecContext(ctx, bind(query), goIDs[index], workspaceID, goRepository, fmt.Sprintf("v1.0.%d", index), []byte("module example.com/private/module\n"), strings.Repeat("a", 64), timestamp, entry.status, entry.claim, entry.verified, userID, now.Add(-2*time.Hour).UnixMilli(), entry.expires.UnixMilli()); err != nil {
			t.Fatal("seed Go expiration fixture:", err)
		}
	}
	goStaging := filepath.Join(root, "go-staging")
	if err := os.Mkdir(goStaging, 0o700); err != nil {
		t.Fatal(err)
	}
	goService, err := gomod.NewService(db, driver, repositoryService, store, gomod.Options{StagingDirectory: goStaging, MaxZipBytes: 1024, MaxFiles: 10, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	goWorker, err := NewGoUploadExpiration(queue, goService)
	if err != nil {
		t.Fatal(err)
	}
	goWorker.clock = func() time.Time { return now }
	if err := goWorker.RunOnce(ctx); err != nil {
		t.Fatal("Go maintenance run:", err)
	}
	for index, expected := range []string{"expired", "expired", "uploaded", "receiving"} {
		var status string
		var claim sql.NullString
		if err := db.QueryRowContext(ctx, bind(`SELECT status, upload_claim_id FROM registry_go_upload_sessions WHERE upload_session_id = ?`), goIDs[index]).Scan(&status, &claim); err != nil || status != expected || claim.Valid {
			t.Fatalf("Go session %d status=%q claim=%t err=%v", index, status, claim.Valid, err)
		}
	}
	goRestarted, err := NewGoUploadExpiration(queue, goService)
	if err != nil {
		t.Fatal(err)
	}
	goRestarted.clock = func() time.Time { return now.Add(runInterval) }
	if err := goRestarted.RunOnce(ctx); err != nil {
		t.Fatal("restart Go maintenance:", err)
	}
	var goJobs, goAttempts int
	if err := db.QueryRowContext(ctx, bind(`SELECT count(*), max(attempts) FROM registry_jobs WHERE idempotency_key = ?`), goExpirationKey).Scan(&goJobs, &goAttempts); err != nil || goJobs != 1 || goAttempts != 0 {
		t.Fatalf("Go recurring job count=%d attempts=%d err=%v", goJobs, goAttempts, err)
	}
	cargoRepository, cargoGrant, cargoToken := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := db.ExecContext(ctx, bind(`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'cargo-maintenance', 'Cargo', ?, ?, ?, 'cargo')`), cargoRepository, workspaceID, userID, timestamp, timestamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, bind(`INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (?, ?, ?, ?, 'publisher', ?, ?)`), cargoGrant, cargoRepository, workspaceID, userID, userID, timestamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, bind(`INSERT INTO registry_cargo_write_tokens (token_id, user_id, workspace_id, repository_id, publisher_grant_id, secret_sha256, created_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`), cargoToken, userID, workspaceID, cargoRepository, cargoGrant, strings.Repeat("a", 64), now.Add(-2*time.Hour).UnixMilli(), now.Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	cargoIDs := []string{uuid.NewString(), uuid.NewString()}
	for index, expires := range []time.Time{now.Add(-time.Minute), now.Add(time.Hour)} {
		query := `INSERT INTO registry_cargo_reservations (reservation_id, workspace_id, repository_id, name, name_identity, version, version_identity, archive_sha256, archive_size, metadata_sha256, token_id, created_by, status, created_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?, '1.0.0', '1.0.0', ?, 1, ?, ?, ?, 'reserved', ?, ?)`
		name := fmt.Sprintf("fixture%d", index)
		if _, err := db.ExecContext(ctx, bind(query), cargoIDs[index], workspaceID, cargoRepository, name, name, strings.Repeat("b", 64), strings.Repeat("c", 64), cargoToken, userID, now.Add(-2*time.Hour).UnixMilli(), expires.UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	cargoService, err := cargo.NewReservationService(db, repositoryService, driver)
	if err != nil {
		t.Fatal(err)
	}
	cargoWorker, err := NewCargoReservationExpiration(queue, cargoService)
	if err != nil {
		t.Fatal(err)
	}
	cargoWorker.clock = func() time.Time { return now }
	if err := cargoWorker.RunOnce(ctx); err != nil {
		t.Fatal("Cargo maintenance run:", err)
	}
	for index, expected := range []string{"expired", "reserved"} {
		var cargoStatus string
		if err := db.QueryRowContext(ctx, bind(`SELECT status FROM registry_cargo_reservations WHERE reservation_id = ?`), cargoIDs[index]).Scan(&cargoStatus); err != nil || cargoStatus != expected {
			t.Fatalf("Cargo reservation %d status=%q err=%v", index, cargoStatus, err)
		}
	}
	cargoRestarted, err := NewCargoReservationExpiration(queue, cargoService)
	if err != nil {
		t.Fatal(err)
	}
	cargoRestarted.clock = func() time.Time { return now.Add(runInterval) }
	if err := cargoRestarted.RunOnce(ctx); err != nil {
		t.Fatal("restart Cargo maintenance:", err)
	}
	var cargoJobs, cargoAttempts int
	if err := db.QueryRowContext(ctx, bind(`SELECT count(*), max(attempts) FROM registry_jobs WHERE idempotency_key = ?`), cargoExpirationKey).Scan(&cargoJobs, &cargoAttempts); err != nil || cargoJobs != 1 || cargoAttempts != 0 {
		t.Fatalf("Cargo recurring job count=%d attempts=%d err=%v", cargoJobs, cargoAttempts, err)
	}
	worker, err := NewUploadExpiration(queue, service)
	if err != nil {
		t.Fatal(err)
	}
	worker.clock = func() time.Time { return now }
	if err := worker.RunOnce(ctx); err != nil {
		t.Fatal("first maintenance run:", err)
	}
	var status string
	if err := db.QueryRowContext(ctx, bind(`SELECT status FROM registry_generic_upload_sessions WHERE upload_session_id = ?`), sessionID).Scan(&status); err != nil || status != "expired" {
		t.Fatalf("session status = %q, %v; want expired", status, err)
	}
	restarted, err := NewUploadExpiration(queue, service)
	if err != nil {
		t.Fatal(err)
	}
	restarted.clock = func() time.Time { return now.Add(30 * time.Second) }
	if err := restarted.RunOnce(ctx); err != nil {
		t.Fatal("restart before next run:", err)
	}
	restarted.clock = func() time.Time { return now.Add(runInterval) }
	if err := restarted.RunOnce(ctx); err != nil {
		t.Fatal("restart at next run:", err)
	}
	var count, attempts int
	if err := db.QueryRowContext(ctx, bind(`SELECT count(*), max(attempts) FROM registry_jobs WHERE idempotency_key = ?`), expirationKey).Scan(&count, &attempts); err != nil || count != 1 || attempts != 0 {
		t.Fatalf("recurring job count=%d attempts=%d err=%v", count, attempts, err)
	}

	started := make(chan struct{})
	restarted.artifacts = blockingExpirer{started: started}
	restarted.clock = func() time.Time { return now.Add(2 * runInterval) }
	inFlight, stop := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { result <- restarted.RunOnce(inFlight) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		stop()
		t.Fatal("worker did not begin expiration")
	}
	stop()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled maintenance returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight maintenance did not cancel")
	}
	restarted.artifacts = service
	restarted.clock = func() time.Time { return now.Add(2*runInterval + leaseDuration + time.Second) }
	if err := restarted.RunOnce(ctx); err != nil {
		t.Fatal("recover canceled claim after lease expiration:", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	done := make(chan struct{})
	go func() { defer close(done); restarted.Run(canceled, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after cancellation")
	}
}
