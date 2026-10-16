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
	if len(first.AppliedVersions) != 2 || first.AppliedVersions[0] != 1 || first.AppliedVersions[1] != 2 {
		t.Fatalf("unexpected first migration report: %+v", first)
	}
	if first.CurrentVersion != 2 || first.TargetVersion != 2 {
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
	if succeeded != 2 {
		t.Fatalf("unexpected successful migration attempts: %d", succeeded)
	}
	var checksumCount int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM registry_migration_checksums").Scan(&checksumCount); err != nil {
		t.Fatal(err)
	}
	if checksumCount != 2 {
		t.Fatalf("unexpected migration checksum count: %d", checksumCount)
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
		"sql/postgres/000001_installation.sql",
		"sql/postgres/000002_identity_workspaces.sql",
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
