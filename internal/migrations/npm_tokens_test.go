package migrations

import (
	"context"
	"database/sql"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
)

func TestSQLiteNPMTokenMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			cfg := sqliteConfig(t)
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exerciseNPMTokenMigration(t, ctx, db, cfg, fail)
		})
	}
}

func exerciseNPMTokenMigration(t *testing.T, ctx context.Context, db *sql.DB, cfg config.Config, fail bool) {
	t.Helper()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
	delete(old, "sql/sqlite/000027_npm_write_tokens.sql")
	delete(old, "sql/postgres/000027_npm_write_tokens.sql")
	delete(old, "sql/sqlite/000028_npm_reservations.sql")
	delete(old, "sql/postgres/000028_npm_reservations.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 26 {
		t.Fatalf("prepare v26 fixture: %+v err=%v", report, err)
	}
	if !fail {
		report, err := Migrate(ctx, db, cfg)
		if err != nil || report.CurrentVersion != 28 || len(report.AppliedVersions) != 2 || report.AppliedVersions[0] != 27 || report.AppliedVersions[1] != 28 {
			t.Fatalf("v27–v28 upgrade failed: %+v err=%v", report, err)
		}
		if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := "sql/sqlite/000027_npm_write_tokens.sql"
	query := `SELECT count(*) FROM sqlite_schema WHERE name = 'registry_npm_write_tokens'`
	if cfg.DatabaseDriver == config.Postgres {
		path = "sql/postgres/000027_npm_write_tokens.sql"
		query = `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'registry_npm_write_tokens'`
	}
	contents, err := fs.ReadFile(embeddedMigrations, path)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(contents), "-- +goose Down", "INSERT INTO nonexistent_npm_failure_fixture VALUES (1);\n-- +goose Down", 1)
	if broken == string(contents) {
		t.Fatal("failed to inject v27 migration failure")
	}
	if _, err := migrateWithFS(ctx, db, cfg, migrationFS(t, path, broken)); err == nil {
		t.Fatal("injected npm credential migration failure succeeded")
	}
	var count int
	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed v27 migration left credential table: count=%d err=%v", count, err)
	}
	if _, err := Migrate(ctx, db, cfg); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("changed migration source was not rejected: %v", err)
	}
}
