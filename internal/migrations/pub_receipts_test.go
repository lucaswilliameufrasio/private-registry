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

func TestSQLitePubReceiptMigration(t *testing.T) {
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
			exercisePubReceiptMigration(t, ctx, db, cfg, fail)
		})
	}
}

func exercisePubReceiptMigration(t *testing.T, ctx context.Context, db *sql.DB, cfg config.Config, fail bool) {
	t.Helper()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
	delete(old, "sql/sqlite/000037_pub_receipts.sql")
	delete(old, "sql/postgres/000037_pub_receipts.sql")
	delete(old, "sql/sqlite/000038_pub_review.sql")
	delete(old, "sql/postgres/000038_pub_review.sql")
	delete(old, "sql/sqlite/000039_pub_publications.sql")
	delete(old, "sql/postgres/000039_pub_publications.sql")
	delete(old, "sql/sqlite/000040_pub_native_uploads.sql")
	delete(old, "sql/postgres/000040_pub_native_uploads.sql")
	delete(old, "sql/sqlite/000041_oci_repository_format.sql")
	delete(old, "sql/postgres/000041_oci_repository_format.sql")
	delete(old, "sql/sqlite/000042_oci_registry.sql")
	delete(old, "sql/postgres/000042_oci_registry.sql")
	delete(old, "sql/sqlite/000043_oci_policies.sql")
	delete(old, "sql/postgres/000043_oci_policies.sql")
	delete(old, "sql/sqlite/000044_invitations_and_oci_review.sql")
	delete(old, "sql/postgres/000044_invitations_and_oci_review.sql")
	delete(old, "sql/sqlite/000045_service_accounts_recovery_passkeys.sql")
	delete(old, "sql/postgres/000045_service_accounts_recovery_passkeys.sql")
	delete(old, "sql/sqlite/000046_email_delivery.sql")
	delete(old, "sql/postgres/000046_email_delivery.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 36 {
		t.Fatalf("prepare v36 fixture: %+v err=%v", report, err)
	}
	p := func(n int) string { return bind(cfg.DatabaseDriver, n) }
	user, workspace, repository, grant, token := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, item := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (` + p(1) + `, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (` + p(1) + `, 'pub-receipt-migration', 'Fixture', ` + p(2) + `, 'now')`, []any{workspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'pub', 'Fixture', ` + p(3) + `, 'now', 'now', 'pub')`, []any{repository, workspace, user}},
		{`INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, 'publisher', ` + p(5) + `, 'now')`, []any{grant, repository, workspace, user, user}},
		{`INSERT INTO registry_pub_write_tokens (token_id, user_id, workspace_id, repository_id, publisher_grant_id, secret_sha256, created_at_ms, expires_at_ms) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, ` + p(6) + `, 1, 100)`, []any{token, user, workspace, repository, grant, strings.Repeat("a", 64)}},
	} {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	ids := make(map[string]string)
	for _, status := range []string{"reserved", "expired", "cancelled"} {
		id := uuid.NewString()
		ids[status] = id
		query := `INSERT INTO registry_pub_reservations (reservation_id, workspace_id, repository_id, name, version, version_identity, tarball_sha256, tarball_size, metadata_sha256, token_id, created_by, status, created_at_ms, expires_at_ms) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, '1.0.0+fixture', '1.0.0', ` + p(5) + `, 7, ` + p(6) + `, ` + p(7) + `, ` + p(8) + `, ` + p(9) + `, 1, 100)`
		if _, err := db.ExecContext(ctx, query, id, workspace, repository, status, strings.Repeat("b", 64), strings.Repeat("c", 64), token, user, status); err != nil {
			t.Fatal(err)
		}
	}
	assertReservations := func() {
		t.Helper()
		for status, id := range ids {
			var name, gotStatus, version, identity, digest, metadata, gotToken, actor string
			var size, invalidated, created, expires int
			query := `SELECT name, status, version, version_identity, tarball_sha256, tarball_size, metadata_sha256, token_id, created_by, recovery_invalidated, created_at_ms, expires_at_ms FROM registry_pub_reservations WHERE reservation_id = ` + p(1)
			if err := db.QueryRowContext(ctx, query, id).Scan(&name, &gotStatus, &version, &identity, &digest, &size, &metadata, &gotToken, &actor, &invalidated, &created, &expires); err != nil || name != status || gotStatus != status || version != "1.0.0+fixture" || identity != "1.0.0" || digest != strings.Repeat("b", 64) || size != 7 || metadata != strings.Repeat("c", 64) || gotToken != token || actor != user || invalidated != 0 || created != 1 || expires != 100 {
				t.Fatalf("reservation %s changed across migration: %v", status, err)
			}
		}
	}
	if !fail {
		report, err := Migrate(ctx, db, cfg)
		if err != nil || report.CurrentVersion != 46 || len(report.AppliedVersions) != 10 || report.AppliedVersions[0] != 37 || report.AppliedVersions[1] != 38 || report.AppliedVersions[2] != 39 || report.AppliedVersions[3] != 40 || report.AppliedVersions[4] != 41 || report.AppliedVersions[5] != 42 || report.AppliedVersions[6] != 43 || report.AppliedVersions[7] != 44 || report.AppliedVersions[8] != 45 || report.AppliedVersions[9] != 46 {
			t.Fatalf("v37 upgrade failed: %+v err=%v", report, err)
		}
		if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
			t.Fatal(err)
		}
		assertReservations()
		return
	}
	path := "sql/sqlite/000037_pub_receipts.sql"
	query := `SELECT count(*) FROM sqlite_schema WHERE name = 'registry_pub_reservations'`
	if cfg.DatabaseDriver == config.Postgres {
		path = "sql/postgres/000037_pub_receipts.sql"
		query = `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'registry_pub_reservations'`
	}
	contents, err := fs.ReadFile(embeddedMigrations, path)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(contents), "-- +goose Down", "INSERT INTO nonexistent_pub_reservation_failure_fixture VALUES (1);\n-- +goose Down", 1)
	if broken == string(contents) {
		t.Fatal("failed to inject Pub receipt migration failure")
	}
	if _, err := migrateWithFS(ctx, db, cfg, migrationFS(t, path, broken)); err == nil {
		t.Fatal("injected Pub receipt migration failure succeeded")
	}
	var count int
	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed Pub receipt migration did not preserve table: count=%d err=%v", count, err)
	}
	assertReservations()
	if _, err := Migrate(ctx, db, cfg); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("changed Pub receipt migration source was not rejected: %v", err)
	}
}
