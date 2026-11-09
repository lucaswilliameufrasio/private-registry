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

func TestSQLiteNPMReviewMigration(t *testing.T) {
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
			exerciseNPMReviewMigration(t, ctx, db, cfg, fail)
		})
	}
}

func exerciseNPMReviewMigration(t *testing.T, ctx context.Context, db *sql.DB, cfg config.Config, fail bool) {
	t.Helper()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
	delete(old, "sql/sqlite/000030_npm_review.sql")
	delete(old, "sql/postgres/000030_npm_review.sql")
	delete(old, "sql/sqlite/000031_npm_publications.sql")
	delete(old, "sql/postgres/000031_npm_publications.sql")
	delete(old, "sql/sqlite/000032_npm_dist_tags.sql")
	delete(old, "sql/postgres/000032_npm_dist_tags.sql")
	delete(old, "sql/sqlite/000033_pub_repository_format.sql")
	delete(old, "sql/postgres/000033_pub_repository_format.sql")
	delete(old, "sql/sqlite/000034_pub_catalog.sql")
	delete(old, "sql/postgres/000034_pub_catalog.sql")
	delete(old, "sql/sqlite/000035_pub_write_tokens.sql")
	delete(old, "sql/postgres/000035_pub_write_tokens.sql")
	delete(old, "sql/sqlite/000036_pub_reservations.sql")
	delete(old, "sql/postgres/000036_pub_reservations.sql")
	delete(old, "sql/sqlite/000037_pub_receipts.sql")
	delete(old, "sql/postgres/000037_pub_receipts.sql")
	delete(old, "sql/sqlite/000038_pub_review.sql")
	delete(old, "sql/postgres/000038_pub_review.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 29 {
		t.Fatalf("prepare v29 fixture: %+v err=%v", report, err)
	}
	if !fail {
		report, err := Migrate(ctx, db, cfg)
		if err != nil || report.CurrentVersion != 38 || len(report.AppliedVersions) != 9 || report.AppliedVersions[0] != 30 || report.AppliedVersions[1] != 31 || report.AppliedVersions[2] != 32 || report.AppliedVersions[3] != 33 || report.AppliedVersions[4] != 34 || report.AppliedVersions[5] != 35 || report.AppliedVersions[6] != 36 || report.AppliedVersions[7] != 37 || report.AppliedVersions[8] != 38 {
			t.Fatalf("v30 upgrade failed: %+v err=%v", report, err)
		}
		if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := "sql/sqlite/000030_npm_review.sql"
	query := `SELECT count(*) FROM sqlite_schema WHERE name IN ('registry_npm_reviewer_grants', 'registry_npm_review_decisions')`
	if cfg.DatabaseDriver == config.Postgres {
		path = "sql/postgres/000030_npm_review.sql"
		query = `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name IN ('registry_npm_reviewer_grants', 'registry_npm_review_decisions')`
	}
	contents, err := fs.ReadFile(embeddedMigrations, path)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(contents), "-- +goose Down", "INSERT INTO nonexistent_npm_failure_fixture VALUES (1);\n-- +goose Down", 1)
	if broken == string(contents) {
		t.Fatal("failed to inject npm review migration failure")
	}
	if _, err := migrateWithFS(ctx, db, cfg, migrationFS(t, path, broken)); err == nil {
		t.Fatal("injected npm review migration failure succeeded")
	}
	var count int
	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed review migration left tables: count=%d err=%v", count, err)
	}
	if _, err := Migrate(ctx, db, cfg); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("changed review migration source was not rejected: %v", err)
	}
}
