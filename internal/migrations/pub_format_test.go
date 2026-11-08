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

func TestSQLitePubFormatUpgrade(t *testing.T) {
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
			exercisePubFormatUpgrade(t, ctx, db, cfg, fail)
		})
	}
}

func exercisePubFormatUpgrade(t *testing.T, ctx context.Context, db *sql.DB, cfg config.Config, fail bool) {
	t.Helper()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
	delete(old, "sql/sqlite/000033_pub_repository_format.sql")
	delete(old, "sql/postgres/000033_pub_repository_format.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 32 {
		t.Fatalf("prepare v32 fixture: %+v err=%v", report, err)
	}
	p := func(n int) string { return bind(cfg.DatabaseDriver, n) }
	user, workspace, repository, pkg, version := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (` + p(1) + `, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (` + p(1) + `, 'pub-upgrade', 'Fixture', ` + p(2) + `, 'now')`, []any{workspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'npm', 'Fixture', ` + p(3) + `, 'now', 'now', 'npm')`, []any{repository, workspace, user}},
		{`INSERT INTO registry_npm_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, 'fixture', ` + p(4) + `, 'now')`, []any{pkg, workspace, repository, user}},
		{`INSERT INTO registry_npm_versions (npm_version_id, workspace_id, repository_id, package_id, version, version_identity, manifest, tarball_sha256, tarball_size, integrity, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, '1.0.0', '1.0.0', '{}', ` + p(5) + `, 12, ` + p(6) + `, ` + p(7) + `, 'now')`, []any{version, workspace, repository, pkg, strings.Repeat("a", 64), "sha512-" + strings.Repeat("A", 86) + "==", user}},
	}
	for _, item := range statements {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	if fail {
		path := "sql/sqlite/000033_pub_repository_format.sql"
		if cfg.DatabaseDriver == config.Postgres {
			path = "sql/postgres/000033_pub_repository_format.sql"
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
			t.Fatal("migration failure was not injected")
		}
		if _, err := migrateWithFS(ctx, db, cfg, migrationFS(t, path, broken)); err == nil {
			t.Fatal("failed Pub migration committed")
		}
	} else {
		report, err := Migrate(ctx, db, cfg)
		if err != nil || report.CurrentVersion != 33 || len(report.AppliedVersions) != 1 || report.AppliedVersions[0] != 33 {
			t.Fatalf("Pub format upgrade: %+v err=%v", report, err)
		}
		if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_npm_versions WHERE npm_version_id = `+p(1), version).Scan(&count); err != nil || count != 1 {
		t.Fatalf("npm version was not preserved: count=%d err=%v", count, err)
	}
	pubRepository := uuid.NewString()
	_, err = db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (`+p(1)+`, `+p(2)+`, 'pub', 'Fixture', `+p(3)+`, 'now', 'now', 'pub')`, pubRepository, workspace, user)
	if (err == nil) == fail {
		t.Fatalf("Pub format acceptance after migration fail=%v err=%v", fail, err)
	}
	if !fail {
		if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET format = 'npm' WHERE repository_id = `+p(1), pubRepository); err == nil {
			t.Fatal("Pub repository format was mutable")
		}
		query := `INSERT INTO registry_npm_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, 'wrong-format', ` + p(4) + `, 'now')`
		if _, err := db.ExecContext(ctx, query, uuid.NewString(), workspace, pubRepository, user); err == nil {
			t.Fatal("npm package referenced a Pub repository")
		}
	}
}
