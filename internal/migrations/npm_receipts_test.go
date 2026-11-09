package migrations

import (
	"context"
	"database/sql"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
)

func TestSQLiteNPMReceiptMigration(t *testing.T) {
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
			exerciseNPMReceiptMigration(t, ctx, db, cfg, fail)
		})
	}
}

func exerciseNPMReceiptMigration(t *testing.T, ctx context.Context, db *sql.DB, cfg config.Config, fail bool) {
	t.Helper()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
	delete(old, "sql/sqlite/000029_npm_receipts.sql")
	delete(old, "sql/postgres/000029_npm_receipts.sql")
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
	delete(old, "sql/sqlite/000039_pub_publications.sql")
	delete(old, "sql/postgres/000039_pub_publications.sql")
	delete(old, "sql/sqlite/000040_pub_native_uploads.sql")
	delete(old, "sql/postgres/000040_pub_native_uploads.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 28 {
		t.Fatalf("prepare v28 fixture: %+v err=%v", report, err)
	}
	p := func(n int) string { return bind(cfg.DatabaseDriver, n) }
	user, workspace, repo, grant, token, reservation := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (` + p(1) + `, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (` + p(1) + `, 'npm-receipt-migration', 'Fixture', ` + p(2) + `, 'now')`, []any{workspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'npm', 'npm', ` + p(3) + `, 'now', 'now', 'npm')`, []any{repo, workspace, user}},
		{`INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, 'publisher', ` + p(5) + `, 'now')`, []any{grant, repo, workspace, user, user}},
		{`INSERT INTO registry_npm_write_tokens (token_id, user_id, workspace_id, repository_id, publisher_grant_id, secret_sha256, created_at_ms, expires_at_ms) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, ` + p(6) + `, 1, 100)`, []any{token, user, workspace, repo, grant, strings.Repeat("a", 64)}},
		{`INSERT INTO registry_npm_reservations (reservation_id, workspace_id, repository_id, name, version, version_identity, tarball_sha256, tarball_size, metadata_sha256, token_id, created_by, status, created_at_ms, expires_at_ms) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, 'fixture', '1.0.0', '1.0.0', ` + p(4) + `, 5, ` + p(5) + `, ` + p(6) + `, ` + p(7) + `, 'reserved', 1, 100)`, []any{reservation, workspace, repo, strings.Repeat("b", 64), strings.Repeat("c", 64), token, user}},
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	path := "sql/sqlite/000029_npm_receipts.sql"
	if cfg.DatabaseDriver == config.Postgres {
		path = "sql/postgres/000029_npm_receipts.sql"
	}
	if fail {
		contents, err := fs.ReadFile(embeddedMigrations, path)
		if err != nil {
			t.Fatal(err)
		}
		broken := strings.Replace(string(contents), "-- +goose Down", "INSERT INTO nonexistent_npm_failure_fixture VALUES (1);\n-- +goose Down", 1)
		if broken == string(contents) {
			t.Fatal("failed to inject receipt migration failure")
		}
		if _, err := migrateWithFS(ctx, db, cfg, migrationFS(t, path, broken)); err == nil {
			t.Fatal("injected receipt migration failure succeeded")
		}
	} else {
		report, err := Migrate(ctx, db, cfg)
		if err != nil || report.CurrentVersion != 40 || len(report.AppliedVersions) != 12 || report.AppliedVersions[0] != 29 || report.AppliedVersions[1] != 30 || report.AppliedVersions[2] != 31 || report.AppliedVersions[3] != 32 || report.AppliedVersions[4] != 33 || report.AppliedVersions[5] != 34 || report.AppliedVersions[6] != 35 || report.AppliedVersions[7] != 36 || report.AppliedVersions[8] != 37 || report.AppliedVersions[9] != 38 || report.AppliedVersions[10] != 39 || report.AppliedVersions[11] != 40 {
			t.Fatalf("v29–v30 upgrade failed: %+v err=%v", report, err)
		}
		if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
			t.Fatal(err)
		}
	}
	var status, hash string
	var size int64
	query := `SELECT status, tarball_sha256, tarball_size FROM registry_npm_reservations WHERE reservation_id = ` + p(1)
	if err := db.QueryRowContext(ctx, query, reservation).Scan(&status, &hash, &size); err != nil || status != "reserved" || hash != strings.Repeat("b", 64) || size != 5 {
		t.Fatalf("v29 migration changed old reservation: status=%q size=%d err=%v", status, size, err)
	}
	if fail {
		if _, err := Migrate(ctx, db, cfg); err == nil || !strings.Contains(err.Error(), "checksum") {
			t.Fatalf("changed receipt migration source was not rejected: %v", err)
		}
	}
}
