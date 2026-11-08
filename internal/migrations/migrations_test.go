package migrations

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
)

func TestMigrateSQLiteIsRepeatableAndPersistsInstallationIdentity(t *testing.T) {
	cfg := sqliteConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDatabase(t, db))

	first, err := Migrate(ctx, db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.AppliedVersions) != 23 {
		t.Fatalf("unexpected first migration report: %+v", first)
	}
	for index, version := range first.AppliedVersions {
		if version != int64(index+1) {
			t.Fatalf("migration %d at position %d; want sequential versions 1–23", version, index)
		}
	}
	if first.CurrentVersion != 23 || first.TargetVersion != 23 {
		t.Fatalf("unexpected migrated version: %+v", first)
	}
	parsedID, err := uuid.Parse(first.InstallationID)
	if err != nil || parsedID.Version() != 7 {
		t.Fatalf("installation identity is not UUIDv7: %q (%v)", first.InstallationID, err)
	}

	second, err := Migrate(ctx, db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.AppliedVersions) != 0 {
		t.Fatalf("repeat migration unexpectedly applied versions: %+v", second.AppliedVersions)
	}
	if second.InstallationID != first.InstallationID {
		t.Fatalf("installation identity changed: got %q, want %q", second.InstallationID, first.InstallationID)
	}

	var succeeded int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM registry_migration_attempts WHERE status = 'succeeded'").Scan(&succeeded); err != nil {
		t.Fatal(err)
	}
	if succeeded != 23 {
		t.Fatalf("unexpected successful migration attempts: %d", succeeded)
	}
	var checksumCount int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM registry_migration_checksums").Scan(&checksumCount); err != nil {
		t.Fatal(err)
	}
	if checksumCount != 23 {
		t.Fatalf("unexpected migration checksum count: %d", checksumCount)
	}
	var credentialTableExists bool
	if err := db.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'registry_local_credentials')").Scan(&credentialTableExists); err != nil {
		t.Fatal(err)
	}
	if !credentialTableExists {
		t.Fatal("local credential table is missing after migration v3")
	}
	for _, tableName := range []string{
		"registry_totp_credentials", "registry_mfa_recovery_codes", "registry_auth_sessions",
		"registry_auth_attempt_buckets", "registry_repositories", "registry_repository_grants",
		"registry_generic_artifact_versions", "registry_generic_upload_sessions",
		"registry_generic_artifact_files", "registry_generic_download_tickets", "registry_jobs", "registry_personal_read_tokens",
	} {
		var tableExists bool
		if err := db.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)", tableName).Scan(&tableExists); err != nil {
			t.Fatal(err)
		}
		if !tableExists {
			t.Fatalf("security table %q is missing after the latest migration", tableName)
		}
	}
}

func TestMigrateRejectsChangedMigrationAndMissingAppliedChecksum(t *testing.T) {
	cfg := sqliteConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDatabase(t, db))

	if _, err := Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	changed := migrationFS(t, "sql/sqlite/000002_identity_workspaces.sql", "-- +goose Up\nCREATE TABLE changed_identity_schema (changed INTEGER);\n")
	if _, err := migrateWithFS(ctx, db, cfg, changed); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("changed migration was not rejected with a checksum error: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM registry_migration_checksums WHERE version_id = 2"); err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(ctx, db, cfg); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("applied migration without a stored checksum was accepted: %v", err)
	}
}

func TestMigrateRecordsTransactionalFailure(t *testing.T) {
	cfg := sqliteConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDatabase(t, db))

	nonTransactional := migrationFS(t, "sql/sqlite/000002_identity_workspaces.sql", "-- +goose Up\n-- +goose NO TRANSACTION\nCREATE TABLE forbidden_non_transactional (id INTEGER);\n")
	if _, err := migrateWithFS(ctx, db, cfg, nonTransactional); err == nil || !strings.Contains(err.Error(), "non-transactional") {
		t.Fatalf("non-transactional migration was not rejected: %v", err)
	}

	invalid := migrationFS(t, "sql/sqlite/000002_identity_workspaces.sql",
		"-- +goose Up\nCREATE TABLE migration_partial_change (id INTEGER);\nTHIS IS NOT SQL;\n")
	if _, err := migrateWithFS(ctx, db, cfg, invalid); err == nil {
		t.Fatal("invalid migration unexpectedly succeeded")
	}
	var status, failureCode string
	if err := db.QueryRowContext(ctx,
		"SELECT status, failure_code FROM registry_migration_attempts WHERE version_id = 2").Scan(&status, &failureCode); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || failureCode != "migration_failed" {
		t.Fatalf("migration failure was not recorded safely: status=%q code=%q", status, failureCode)
	}
	var tableExists bool
	if err := db.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'registry_users')").Scan(&tableExists); err != nil {
		t.Fatal(err)
	}
	if tableExists {
		t.Fatal("failed transactional migration left its schema changes behind")
	}
	if err := db.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'migration_partial_change')").Scan(&tableExists); err != nil {
		t.Fatal(err)
	}
	if tableExists {
		t.Fatal("failed transactional migration retained a statement executed before the error")
	}
}

func TestMigrateReconcilesAttemptInterruptedAfterCommit(t *testing.T) {
	cfg := sqliteConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDatabase(t, db))
	if _, err := Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO registry_migration_attempts (attempt_id, version_id, status, started_at) VALUES (?, 2, 'running', ?)",
		"synthetic-interrupted-attempt", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	var status string
	var failureCode sql.NullString
	if err := db.QueryRowContext(ctx,
		"SELECT status, failure_code FROM registry_migration_attempts WHERE attempt_id = ?", "synthetic-interrupted-attempt").Scan(&status, &failureCode); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" || failureCode.Valid {
		t.Fatalf("committed interrupted migration was not reconciled: status=%q failure=%q", status, failureCode.String)
	}
}

func TestMigrateSerializesConcurrentSQLiteCallers(t *testing.T) {
	cfg := sqliteConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	firstDB, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	secondDB, err := database.Open(ctx, cfg)
	if err != nil {
		_ = firstDB.Close()
		t.Fatal(err)
	}
	t.Cleanup(closeDatabase(t, firstDB))
	t.Cleanup(closeDatabase(t, secondDB))

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, db := range []*sql.DB{firstDB, secondDB} {
		go func(db *sql.DB) {
			<-start
			_, err := Migrate(ctx, db, cfg)
			results <- err
		}(db)
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}

	var installations int
	if err := firstDB.QueryRowContext(ctx, "SELECT count(*) FROM registry_installation").Scan(&installations); err != nil {
		t.Fatal(err)
	}
	if installations != 1 {
		t.Fatalf("concurrent migration created %d installations", installations)
	}
}

func TestSQLiteUpgradePreservesExistingGenericRepository(t *testing.T) {
	cfg := sqliteConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDatabase(t, db))
	path := "sql/sqlite/000001_installation.sql"
	first, err := fs.ReadFile(embeddedMigrations, path)
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, path, string(first)).(fstest.MapFS)
	delete(old, "sql/sqlite/000017_go_modules.sql")
	delete(old, "sql/postgres/000017_go_modules.sql")
	delete(old, "sql/sqlite/000018_cargo_repository_format.sql")
	delete(old, "sql/postgres/000018_cargo_repository_format.sql")
	delete(old, "sql/sqlite/000019_cargo_catalog.sql")
	delete(old, "sql/postgres/000019_cargo_catalog.sql")
	delete(old, "sql/sqlite/000020_cargo_write_tokens.sql")
	delete(old, "sql/postgres/000020_cargo_write_tokens.sql")
	delete(old, "sql/sqlite/000021_cargo_reservations.sql")
	delete(old, "sql/postgres/000021_cargo_reservations.sql")
	delete(old, "sql/sqlite/000022_cargo_receipts.sql")
	delete(old, "sql/postgres/000022_cargo_receipts.sql")
	delete(old, "sql/sqlite/000023_cargo_review.sql")
	delete(old, "sql/postgres/000023_cargo_review.sql")
	report, err := migrateWithFS(ctx, db, cfg, old)
	if err != nil || report.CurrentVersion != 16 {
		t.Fatalf("prepare v16 schema: report=%+v err=%v", report, err)
	}
	userID, workspaceID, repositoryID, versionID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (?, 'Synthetic', ?, ?)`, userID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (?, 'upgrade', 'Upgrade', ?, ?)`, workspaceID, userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at) VALUES (?, ?, 'assets', 'Assets', ?, ?, ?)`, repositoryID, workspaceID, userID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_generic_artifact_versions (artifact_version_id, workspace_id, repository_id, collection_name, version_label, status, created_by, created_at, published_at) VALUES (?, ?, ?, 'fixture', 'v1', 'published', ?, ?, ?)`, versionID, workspaceID, repositoryID, userID, now, now); err != nil {
		t.Fatal(err)
	}
	fileID, digest := uuid.NewString(), strings.Repeat("a", 64)
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_generic_artifact_files (artifact_file_id, artifact_version_id, workspace_id, repository_id, path, content_type, size_bytes, sha256, created_by, created_at) VALUES (?, ?, ?, ?, 'fixture.bin', 'application/octet-stream', 12, ?, ?, ?)`, fileID, versionID, workspaceID, repositoryID, digest, userID, now); err != nil {
		t.Fatal(err)
	}
	report, err = Migrate(ctx, db, cfg)
	if err != nil || report.CurrentVersion != 23 || len(report.AppliedVersions) != 7 || report.AppliedVersions[0] != 17 || report.AppliedVersions[1] != 18 || report.AppliedVersions[2] != 19 || report.AppliedVersions[3] != 20 || report.AppliedVersions[4] != 21 || report.AppliedVersions[5] != 22 || report.AppliedVersions[6] != 23 {
		t.Fatalf("upgrade to v23: report=%+v err=%v", report, err)
	}
	var format, retained, status, publishedAt string
	if err := db.QueryRowContext(ctx, `SELECT r.format, v.artifact_version_id, v.status, v.published_at FROM registry_repositories r JOIN registry_generic_artifact_versions v ON v.repository_id = r.repository_id WHERE r.repository_id = ?`, repositoryID).Scan(&format, &retained, &status, &publishedAt); err != nil || format != "generic" || retained != versionID || status != "published" || publishedAt != now {
		t.Fatalf("upgrade changed existing repository: format=%q version=%q status=%q err=%v", format, retained, status, err)
	}
	var retainedDigest string
	if err := db.QueryRowContext(ctx, `SELECT sha256 FROM registry_generic_artifact_files WHERE artifact_file_id = ? AND artifact_version_id = ?`, fileID, versionID).Scan(&retainedDigest); err != nil || retainedDigest != digest {
		t.Fatalf("upgrade changed existing file reference: err=%v", err)
	}
}

func sqliteConfig(t *testing.T) config.Config {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "registry-data")
	return config.Config{
		DataDir:              dataDir,
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          filepath.Join(dataDir, "registry.sqlite"),
		DatabaseMaxOpenConns: 4,
	}
}

func migrationFS(t *testing.T, path, contents string) fs.FS {
	t.Helper()
	files := make(map[string][]byte)
	for _, filename := range []string{
		"sql/sqlite/000001_installation.sql",
		"sql/sqlite/000002_identity_workspaces.sql",
		"sql/sqlite/000003_local_bootstrap.sql",
		"sql/sqlite/000004_mfa_credentials.sql",
		"sql/sqlite/000005_auth_sessions.sql",
		"sql/sqlite/000006_auth_attempt_buckets.sql",
		"sql/sqlite/000007_repositories_visibility.sql",
		"sql/sqlite/000008_repository_grants.sql",
		"sql/sqlite/000009_generic_artifacts.sql",
		"sql/sqlite/000010_artifact_download_tickets.sql",
		"sql/sqlite/000011_jobs.sql",
		"sql/sqlite/000012_generic_logical_quotas.sql",
		"sql/sqlite/000013_quota_revisions.sql",
		"sql/sqlite/000014_job_dead_letter.sql",
		"sql/sqlite/000015_personal_read_tokens.sql",
		"sql/sqlite/000016_recovery_job_hold.sql",
		"sql/sqlite/000017_go_modules.sql",
		"sql/sqlite/000018_cargo_repository_format.sql",
		"sql/sqlite/000019_cargo_catalog.sql",
		"sql/sqlite/000020_cargo_write_tokens.sql",
		"sql/sqlite/000021_cargo_reservations.sql",
		"sql/sqlite/000022_cargo_receipts.sql",
		"sql/sqlite/000023_cargo_review.sql",
		"sql/postgres/000001_installation.sql",
		"sql/postgres/000002_identity_workspaces.sql",
		"sql/postgres/000003_local_bootstrap.sql",
		"sql/postgres/000004_mfa_credentials.sql",
		"sql/postgres/000005_auth_sessions.sql",
		"sql/postgres/000006_auth_attempt_buckets.sql",
		"sql/postgres/000007_repositories_visibility.sql",
		"sql/postgres/000008_repository_grants.sql",
		"sql/postgres/000009_generic_artifacts.sql",
		"sql/postgres/000010_artifact_download_tickets.sql",
		"sql/postgres/000011_jobs.sql",
		"sql/postgres/000012_generic_logical_quotas.sql",
		"sql/postgres/000013_quota_revisions.sql",
		"sql/postgres/000014_job_dead_letter.sql",
		"sql/postgres/000015_personal_read_tokens.sql",
		"sql/postgres/000016_recovery_job_hold.sql",
		"sql/postgres/000017_go_modules.sql",
		"sql/postgres/000018_cargo_repository_format.sql",
		"sql/postgres/000019_cargo_catalog.sql",
		"sql/postgres/000020_cargo_write_tokens.sql",
		"sql/postgres/000021_cargo_reservations.sql",
		"sql/postgres/000022_cargo_receipts.sql",
		"sql/postgres/000023_cargo_review.sql",
	} {
		data, err := fs.ReadFile(embeddedMigrations, filename)
		if err != nil {
			t.Fatalf("read embedded test migration %q: %v", filename, err)
		}
		files[filename] = data
	}
	files[path] = []byte(contents)
	mapFiles := make(fstest.MapFS, len(files))
	for filename, data := range files {
		mapFiles[filename] = &fstest.MapFile{Data: data}
	}
	return mapFiles
}

func closeDatabase(t *testing.T, db *sql.DB) func() {
	t.Helper()
	return func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	}
}
