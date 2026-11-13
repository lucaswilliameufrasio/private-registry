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

func TestSQLitePubCatalogMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			cfg := sqliteConfig(t)
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exercisePubCatalogMigration(t, ctx, db, cfg, fail)
		})
	}
}

func exercisePubCatalogMigration(t *testing.T, ctx context.Context, db *sql.DB, cfg config.Config, fail bool) {
	t.Helper()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
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
	delete(old, "sql/sqlite/000047_email_failures.sql")
	delete(old, "sql/postgres/000047_email_failures.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 33 {
		t.Fatalf("prepare v33 fixture: %+v err=%v", report, err)
	}
	if fail {
		path := "sql/sqlite/000034_pub_catalog.sql"
		query := `SELECT count(*) FROM sqlite_schema WHERE name IN ('registry_pub_packages', 'registry_pub_versions')`
		if cfg.DatabaseDriver == config.Postgres {
			path = "sql/postgres/000034_pub_catalog.sql"
			query = `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name IN ('registry_pub_packages', 'registry_pub_versions')`
		}
		contents, err := fs.ReadFile(embeddedMigrations, path)
		if err != nil {
			t.Fatal(err)
		}
		broken := strings.Replace(string(contents), "-- +goose Down", "INSERT INTO nonexistent_pub_failure_fixture VALUES (1);\n-- +goose Down", 1)
		if broken == string(contents) {
			t.Fatal("failed to inject Pub catalog migration failure")
		}
		if _, err := migrateWithFS(ctx, db, cfg, migrationFS(t, path, broken)); err == nil {
			t.Fatal("failed Pub catalog migration committed")
		}
		var count int
		if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed Pub catalog migration left tables: count=%d err=%v", count, err)
		}
		return
	}
	report, err := Migrate(ctx, db, cfg)
	if err != nil || report.CurrentVersion != 47 || len(report.AppliedVersions) != 14 || report.AppliedVersions[0] != 34 || report.AppliedVersions[1] != 35 || report.AppliedVersions[2] != 36 || report.AppliedVersions[3] != 37 || report.AppliedVersions[4] != 38 || report.AppliedVersions[5] != 39 || report.AppliedVersions[6] != 40 || report.AppliedVersions[7] != 41 || report.AppliedVersions[8] != 42 || report.AppliedVersions[9] != 43 || report.AppliedVersions[10] != 44 || report.AppliedVersions[11] != 45 || report.AppliedVersions[12] != 46 || report.AppliedVersions[13] != 47 {
		t.Fatalf("Pub catalog upgrade: %+v err=%v", report, err)
	}
	if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
		t.Fatal(err)
	}
	p := func(n int) string { return bind(cfg.DatabaseDriver, n) }
	user, workspace, repository, npmRepo, pkg := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (` + p(1) + `, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (` + p(1) + `, 'pub-catalog', 'Fixture', ` + p(2) + `, 'now')`, []any{workspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'pub', 'Fixture', ` + p(3) + `, 'now', 'now', 'pub')`, []any{repository, workspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'npm', 'Fixture', ` + p(3) + `, 'now', 'now', 'npm')`, []any{npmRepo, workspace, user}},
	}
	for _, item := range statements {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	packageQuery := `INSERT INTO registry_pub_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, 'now')`
	if _, err := db.ExecContext(ctx, packageQuery, pkg, workspace, repository, "fixture", user); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, packageQuery, uuid.NewString(), workspace, npmRepo, "fixture", user); err == nil {
		t.Fatal("Pub package referenced npm repository")
	}
	versionQuery := `INSERT INTO registry_pub_versions (pub_version_id, workspace_id, repository_id, package_id, version, version_identity, manifest, tarball_sha256, tarball_size, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, ` + p(6) + `, 'name: fixture', ` + p(7) + `, 12, ` + p(8) + `, 'now')`
	version := uuid.NewString()
	if _, err := db.ExecContext(ctx, versionQuery, version, workspace, repository, pkg, "1.0.0+first", "1.0.0", strings.Repeat("a", 64), user); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, versionQuery, uuid.NewString(), workspace, repository, pkg, "1.0.0+second", "1.0.0", strings.Repeat("b", 64), user); err == nil {
		t.Fatal("Pub version identity collision was accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_pub_versions SET tarball_size = 13 WHERE pub_version_id = `+p(1), version); err == nil {
		t.Fatal("Pub version content was mutable")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM registry_pub_versions WHERE pub_version_id = `+p(1), version); err == nil {
		t.Fatal("Pub version content was deleted")
	}
}
