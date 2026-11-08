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

func TestSQLiteCargoReceiptUpgradePreservesReservations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cfg := sqliteConfig(t)
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exerciseCargoReceiptUpgrade(t, ctx, db, cfg)
}

func exerciseCargoReceiptUpgrade(t *testing.T, ctx context.Context, db *sql.DB, cfg config.Config) {
	t.Helper()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
	delete(old, "sql/sqlite/000022_cargo_receipts.sql")
	delete(old, "sql/postgres/000022_cargo_receipts.sql")
	delete(old, "sql/sqlite/000023_cargo_review.sql")
	delete(old, "sql/postgres/000023_cargo_review.sql")
	delete(old, "sql/sqlite/000024_cargo_publications.sql")
	delete(old, "sql/postgres/000024_cargo_publications.sql")
	delete(old, "sql/sqlite/000025_npm_repository_format.sql")
	delete(old, "sql/postgres/000025_npm_repository_format.sql")
	delete(old, "sql/sqlite/000026_npm_catalog.sql")
	delete(old, "sql/postgres/000026_npm_catalog.sql")
	delete(old, "sql/sqlite/000027_npm_write_tokens.sql")
	delete(old, "sql/postgres/000027_npm_write_tokens.sql")
	delete(old, "sql/sqlite/000028_npm_reservations.sql")
	delete(old, "sql/postgres/000028_npm_reservations.sql")
	delete(old, "sql/sqlite/000029_npm_receipts.sql")
	delete(old, "sql/postgres/000029_npm_receipts.sql")
	delete(old, "sql/sqlite/000030_npm_review.sql")
	delete(old, "sql/postgres/000030_npm_review.sql")
	delete(old, "sql/sqlite/000031_npm_publications.sql")
	delete(old, "sql/postgres/000031_npm_publications.sql")
	delete(old, "sql/sqlite/000032_npm_dist_tags.sql")
	delete(old, "sql/postgres/000032_npm_dist_tags.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 21 {
		t.Fatalf("prepare v21 fixture: %+v err=%v", report, err)
	}
	p := func(n int) string { return bind(cfg.DatabaseDriver, n) }
	user, workspace, repository, grant, token := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (` + p(1) + `, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (` + p(1) + `, 'receipt-upgrade', 'Receipt', ` + p(2) + `, 'now')`, []any{workspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'cargo', 'Cargo', ` + p(3) + `, 'now', 'now', 'cargo')`, []any{repository, workspace, user}},
		{`INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, 'publisher', ` + p(5) + `, 'now')`, []any{grant, repository, workspace, user, user}},
		{`INSERT INTO registry_cargo_write_tokens (token_id, user_id, workspace_id, repository_id, publisher_grant_id, secret_sha256, created_at_ms, expires_at_ms) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, ` + p(6) + `, 1, 100)`, []any{token, user, workspace, repository, grant, strings.Repeat("a", 64)}},
	}
	for _, item := range statements {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	ids := []string{uuid.NewString(), uuid.NewString()}
	for index, status := range []string{"reserved", "cancelled"} {
		query := `INSERT INTO registry_cargo_reservations (reservation_id, workspace_id, repository_id, name, name_identity, version, version_identity, archive_sha256, archive_size, metadata_sha256, token_id, created_by, status, created_at_ms, expires_at_ms) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, '1.0.0', '1.0.0', ` + p(6) + `, 12, ` + p(7) + `, ` + p(8) + `, ` + p(9) + `, ` + p(10) + `, 1, 100)`
		name := []string{"fixture_one", "fixture_two"}[index]
		if _, err := db.ExecContext(ctx, query, ids[index], workspace, repository, name, name, strings.Repeat("b", 64), strings.Repeat("c", 64), token, user, status); err != nil {
			t.Fatal(err)
		}
	}
	report, err := Migrate(ctx, db, cfg)
	if err != nil || report.CurrentVersion != 32 || len(report.AppliedVersions) != 11 || report.AppliedVersions[0] != 22 || report.AppliedVersions[1] != 23 || report.AppliedVersions[2] != 24 || report.AppliedVersions[3] != 25 || report.AppliedVersions[4] != 26 || report.AppliedVersions[5] != 27 || report.AppliedVersions[6] != 28 || report.AppliedVersions[7] != 29 || report.AppliedVersions[8] != 30 || report.AppliedVersions[9] != 31 || report.AppliedVersions[10] != 32 {
		t.Fatalf("upgrade to v30: %+v err=%v", report, err)
	}
	if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
		t.Fatal(err)
	}
	for index, expected := range []string{"reserved", "cancelled"} {
		var status string
		var verified, hold int
		var claim, entry sql.NullString
		query := `SELECT status, object_verified, review_hold, upload_claim_id, index_entry FROM registry_cargo_reservations WHERE reservation_id = ` + p(1)
		if err := db.QueryRowContext(ctx, query, ids[index]).Scan(&status, &verified, &hold, &claim, &entry); err != nil || status != expected || verified != 0 || hold != 0 || claim.Valid || entry.Valid {
			t.Fatalf("reservation changed during upgrade: index=%d err=%v", index, err)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET status = 'reserved' WHERE reservation_id = `+p(1), ids[1]); err == nil {
		t.Fatal("terminal reservation became mutable after upgrade")
	}
}
