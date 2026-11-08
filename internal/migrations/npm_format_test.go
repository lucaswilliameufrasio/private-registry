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
	"github.com/pressly/goose/v3"
	"private-registry/internal/config"
	"private-registry/internal/database"
)

func TestSQLiteNPMFormatUpgradePreservesExistingReferences(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			cfg := sqliteConfig(t)
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exerciseNPMFormatUpgrade(t, ctx, db, cfg, fail)
		})
	}
}

func exerciseNPMFormatUpgrade(t *testing.T, ctx context.Context, db *sql.DB, cfg config.Config, fail bool) {
	t.Helper()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
	delete(old, "sql/sqlite/000025_npm_repository_format.sql")
	delete(old, "sql/postgres/000025_npm_repository_format.sql")
	delete(old, "sql/sqlite/000026_npm_catalog.sql")
	delete(old, "sql/postgres/000026_npm_catalog.sql")
	delete(old, "sql/sqlite/000027_npm_write_tokens.sql")
	delete(old, "sql/postgres/000027_npm_write_tokens.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 24 {
		t.Fatalf("prepare v24 fixture: %+v err=%v", report, err)
	}
	p := func(n int) string { return bind(cfg.DatabaseDriver, n) }
	user, workspace := uuid.NewString(), uuid.NewString()
	genericRepo, goRepo, cargoRepo := uuid.NewString(), uuid.NewString(), uuid.NewString()
	artifact, cargoPackage, cargoVersion := uuid.NewString(), uuid.NewString(), uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (` + p(1) + `, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (` + p(1) + `, 'npm-upgrade', 'Fixture', ` + p(2) + `, 'now')`, []any{workspace, user}},
		{`INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, created_by, created_at, updated_at) VALUES (` + p(1) + `, ` + p(2) + `, 'owner', ` + p(3) + `, 'now', 'now')`, []any{workspace, user, user}},
	}
	for _, item := range statements {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct{ id, slug, format string }{{genericRepo, "files", "generic"}, {goRepo, "go-modules", "go"}, {cargoRepo, "cargo", "cargo"}} {
		query := `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format, logical_quota_bytes, logical_quota_revision, review_required, review_revision) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, 'Fixture', ` + p(4) + `, 'now', 'now', ` + p(5) + `, 12345, 4, 1, 7)`
		if _, err := db.ExecContext(ctx, query, item.id, workspace, item.slug, user, item.format); err != nil {
			t.Fatal(err)
		}
	}
	statements = []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_generic_artifact_versions (artifact_version_id, workspace_id, repository_id, collection_name, version_label, status, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, 'fixture', 'v1', 'receiving', ` + p(4) + `, 'now')`, []any{artifact, workspace, genericRepo, user}},
		{`INSERT INTO registry_go_private_prefixes (workspace_id, repository_id, prefix) VALUES (` + p(1) + `, ` + p(2) + `, 'example.com/private')`, []any{workspace, goRepo}},
		{`INSERT INTO registry_cargo_packages (package_id, workspace_id, repository_id, name, name_identity, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, 'fixture', 'fixture', ` + p(4) + `, 'now')`, []any{cargoPackage, workspace, cargoRepo, user}},
		{`INSERT INTO registry_cargo_versions (cargo_version_id, workspace_id, repository_id, package_id, version, version_identity, index_entry, archive_sha256, archive_size, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, '1.0.0', '1.0.0', '{}', ` + p(5) + `, 12, ` + p(6) + `, 'now')`, []any{cargoVersion, workspace, cargoRepo, cargoPackage, strings.Repeat("a", 64), user}},
	}
	for _, item := range statements {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	if cfg.DatabaseDriver == config.SQLite && !fail {
		engineFS, err := fs.Sub(embeddedMigrations, "sql/sqlite")
		if err != nil {
			t.Fatal(err)
		}
		provider, err := goose.NewProvider(goose.DialectSQLite3, db, engineFS, goose.WithDisableGlobalRegistry(true), goose.WithLogger(goose.NopLogger()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.UpByOne(ctx); err == nil {
			t.Fatal("v25 rebuild ran without its dedicated connection")
		}
	}
	if fail {
		path := "sql/sqlite/000025_npm_repository_format.sql"
		if cfg.DatabaseDriver == config.Postgres {
			path = "sql/postgres/000025_npm_repository_format.sql"
		}
		contents, err := fs.ReadFile(embeddedMigrations, path)
		if err != nil {
			t.Fatal(err)
		}
		broken := strings.Replace(string(contents), "-- +goose Down", "SELECT 1 / 0;\n-- +goose Down", 1)
		if cfg.DatabaseDriver == config.SQLite {
			broken = strings.Replace(string(contents), "INSERT INTO registry_format_migration_guard SELECT count(*) FROM pragma_foreign_key_check;", "INSERT INTO registry_format_migration_guard VALUES (1);", 1)
		}
		if broken == string(contents) {
			t.Fatal("failed to inject migration failure")
		}
		if _, err := migrateWithFS(ctx, db, cfg, migrationFS(t, path, broken)); err == nil {
			t.Fatal("injected v25 failure succeeded")
		}
	} else {
		report, err := Migrate(ctx, db, cfg)
		if err != nil || report.CurrentVersion != 27 || len(report.AppliedVersions) != 3 || report.AppliedVersions[0] != 25 || report.AppliedVersions[1] != 26 || report.AppliedVersions[2] != 27 {
			t.Fatalf("v25–v27 upgrade: %+v err=%v", report, err)
		}
		if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		query string
		id    string
	}{
		{`SELECT count(*) FROM registry_generic_artifact_versions WHERE artifact_version_id = ` + p(1), artifact},
		{`SELECT count(*) FROM registry_go_private_prefixes WHERE repository_id = ` + p(1), goRepo},
		{`SELECT count(*) FROM registry_cargo_versions WHERE cargo_version_id = ` + p(1), cargoVersion},
	} {
		var count int
		if err := db.QueryRowContext(ctx, item.query, item.id).Scan(&count); err != nil || count != 1 {
			t.Fatalf("existing format reference lost: count=%d err=%v", count, err)
		}
	}
	var quota, revision, required, reviewRevision int
	query := `SELECT logical_quota_bytes, logical_quota_revision, review_required, review_revision FROM registry_repositories WHERE repository_id = ` + p(1)
	if err := db.QueryRowContext(ctx, query, cargoRepo).Scan(&quota, &revision, &required, &reviewRevision); err != nil || quota != 12345 || revision != 4 || required != 1 || reviewRevision != 7 {
		t.Fatalf("repository policy changed on upgrade: %v", err)
	}
	npmRepo := uuid.NewString()
	query = `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'npm', 'npm', ` + p(3) + `, 'now', 'now', 'npm')`
	_, insertErr := db.ExecContext(ctx, query, npmRepo, workspace, user)
	if (insertErr != nil) != fail {
		t.Fatalf("npm format availability mismatch after upgrade: %v", insertErr)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET format = 'generic' WHERE repository_id = `+p(1), cargoRepo); err == nil {
		t.Fatal("repository format became mutable")
	}
	if cfg.DatabaseDriver == config.SQLite {
		assertPoolForeignKeys(t, ctx, db)
		var violations int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_foreign_key_check`).Scan(&violations); err != nil || violations != 0 {
			t.Fatalf("foreign-key violations after npm format upgrade: count=%d err=%v", violations, err)
		}
	}
}
