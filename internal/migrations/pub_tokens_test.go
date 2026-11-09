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

func TestSQLitePubWriteTokenMigration(t *testing.T) {
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
			exercisePubWriteTokenMigration(t, ctx, db, cfg, fail)
		})
	}
}

func exercisePubWriteTokenMigration(t *testing.T, ctx context.Context, db *sql.DB, cfg config.Config, fail bool) {
	t.Helper()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
	delete(old, "sql/sqlite/000035_pub_write_tokens.sql")
	delete(old, "sql/postgres/000035_pub_write_tokens.sql")
	delete(old, "sql/sqlite/000036_pub_reservations.sql")
	delete(old, "sql/postgres/000036_pub_reservations.sql")
	delete(old, "sql/sqlite/000037_pub_receipts.sql")
	delete(old, "sql/postgres/000037_pub_receipts.sql")
	delete(old, "sql/sqlite/000038_pub_review.sql")
	delete(old, "sql/postgres/000038_pub_review.sql")
	delete(old, "sql/sqlite/000039_pub_publications.sql")
	delete(old, "sql/postgres/000039_pub_publications.sql")
	delete(old, "sql/sqlite/000040_pub_native_uploads.sql")
	delete(old, "sql/postgres/000040_pub_native_uploads.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 34 {
		t.Fatalf("prepare v34 fixture: %+v err=%v", report, err)
	}
	if !fail {
		report, err := Migrate(ctx, db, cfg)
		if err != nil || report.CurrentVersion != 40 || len(report.AppliedVersions) != 6 || report.AppliedVersions[0] != 35 || report.AppliedVersions[1] != 36 || report.AppliedVersions[2] != 37 || report.AppliedVersions[3] != 38 || report.AppliedVersions[4] != 39 || report.AppliedVersions[5] != 40 {
			t.Fatalf("v35 upgrade failed: %+v err=%v", report, err)
		}
		if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := "sql/sqlite/000035_pub_write_tokens.sql"
	query := `SELECT count(*) FROM sqlite_schema WHERE name = 'registry_pub_write_tokens'`
	if cfg.DatabaseDriver == config.Postgres {
		path = "sql/postgres/000035_pub_write_tokens.sql"
		query = `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'registry_pub_write_tokens'`
	}
	contents, err := fs.ReadFile(embeddedMigrations, path)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(contents), "-- +goose Down", "INSERT INTO nonexistent_pub_token_failure_fixture VALUES (1);\n-- +goose Down", 1)
	if broken == string(contents) {
		t.Fatal("failed to inject Pub credential migration failure")
	}
	if _, err := migrateWithFS(ctx, db, cfg, migrationFS(t, path, broken)); err == nil {
		t.Fatal("injected Pub credential migration failure succeeded")
	}
	var count int
	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed Pub credential migration left table: count=%d err=%v", count, err)
	}
	if _, err := Migrate(ctx, db, cfg); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("changed Pub credential migration source was not rejected: %v", err)
	}
}
