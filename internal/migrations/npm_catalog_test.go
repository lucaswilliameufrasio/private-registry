package migrations

import (
	"context"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/npm"
)

func TestSQLiteNPMCatalogConstraints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg := sqliteConfig(t)
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	exerciseNPMCatalogConstraints(t, ctx, db, cfg.DatabaseDriver)
}

func TestSQLiteNPMCatalogUpgradeAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			exerciseSQLiteNPMCatalogUpgrade(t, fail)
		})
	}
}

func exerciseSQLiteNPMCatalogUpgrade(t *testing.T, fail bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cfg := sqliteConfig(t)
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exerciseNPMCatalogUpgrade(t, ctx, db, cfg, fail)
}

func exerciseNPMCatalogUpgrade(t *testing.T, ctx context.Context, db *sql.DB, cfg config.Config, fail bool) {
	t.Helper()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
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
	delete(old, "sql/sqlite/000033_pub_repository_format.sql")
	delete(old, "sql/postgres/000033_pub_repository_format.sql")
	delete(old, "sql/sqlite/000034_pub_catalog.sql")
	delete(old, "sql/postgres/000034_pub_catalog.sql")
	delete(old, "sql/sqlite/000035_pub_write_tokens.sql")
	delete(old, "sql/postgres/000035_pub_write_tokens.sql")
	delete(old, "sql/sqlite/000036_pub_reservations.sql")
	delete(old, "sql/postgres/000036_pub_reservations.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 25 {
		t.Fatalf("prepare v25 fixture: %+v err=%v", report, err)
	}
	if !fail {
		report, err := Migrate(ctx, db, cfg)
		if err != nil || report.CurrentVersion != 36 || len(report.AppliedVersions) != 11 || report.AppliedVersions[0] != 26 || report.AppliedVersions[1] != 27 || report.AppliedVersions[2] != 28 || report.AppliedVersions[3] != 29 || report.AppliedVersions[4] != 30 || report.AppliedVersions[5] != 31 || report.AppliedVersions[6] != 32 || report.AppliedVersions[7] != 33 || report.AppliedVersions[8] != 34 || report.AppliedVersions[9] != 35 || report.AppliedVersions[10] != 36 {
			t.Fatalf("v26–v30 upgrade failed: %+v err=%v", report, err)
		}
		if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
			t.Fatal(err)
		}
		exerciseNPMCatalogConstraints(t, ctx, db, cfg.DatabaseDriver)
		return
	}
	path := "sql/sqlite/000026_npm_catalog.sql"
	if cfg.DatabaseDriver == config.Postgres {
		path = "sql/postgres/000026_npm_catalog.sql"
	}
	contents, err := fs.ReadFile(embeddedMigrations, path)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(contents), "-- +goose Down", "INSERT INTO nonexistent_npm_failure_fixture VALUES (1);\n-- +goose Down", 1)
	if broken == string(contents) {
		t.Fatal("failed to inject v26 migration failure")
	}
	if _, err := migrateWithFS(ctx, db, cfg, migrationFS(t, path, broken)); err == nil {
		t.Fatal("injected npm catalog migration failure succeeded")
	}
	var count int
	query := `SELECT count(*) FROM sqlite_schema WHERE name IN ('registry_npm_packages', 'registry_npm_versions')`
	if cfg.DatabaseDriver == config.Postgres {
		query = `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name IN ('registry_npm_packages', 'registry_npm_versions')`
	}
	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed v26 migration left catalog tables: count=%d err=%v", count, err)
	}
	if _, err := Migrate(ctx, db, cfg); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("changed migration source was not rejected: %v", err)
	}
}

func exerciseNPMCatalogConstraints(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver) {
	t.Helper()
	p := func(n int) string { return bind(driver, n) }
	user, workspace, otherWorkspace, npmRepo, otherRepo, goRepo := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (` + p(1) + `, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (` + p(1) + `, 'npm-catalog-one', 'One', ` + p(2) + `, 'now')`, []any{workspace, user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (` + p(1) + `, 'npm-catalog-two', 'Two', ` + p(2) + `, 'now')`, []any{otherWorkspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'npm', 'npm', ` + p(3) + `, 'now', 'now', 'npm')`, []any{npmRepo, workspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'npm', 'npm', ` + p(3) + `, 'now', 'now', 'npm')`, []any{otherRepo, otherWorkspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'go', 'Go', ` + p(3) + `, 'now', 'now', 'go')`, []any{goRepo, workspace, user}},
	}
	for _, item := range statements {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	packageQuery := `INSERT INTO registry_npm_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, 'now')`
	packageID := uuid.NewString()
	if _, err := db.ExecContext(ctx, packageQuery, packageID, workspace, npmRepo, "@fixture/pkg", user); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ workspace, repository, name string }{
		{workspace, npmRepo, "@fixture/pkg"},
		{otherWorkspace, npmRepo, "other"},
		{workspace, goRepo, "other"},
		{workspace, npmRepo, "UPPER"},
	} {
		if _, err := db.ExecContext(ctx, packageQuery, uuid.NewString(), item.workspace, item.repository, item.name, user); err == nil {
			t.Fatal("invalid npm package insertion was accepted")
		}
	}
	if _, err := db.ExecContext(ctx, packageQuery, uuid.NewString(), otherWorkspace, otherRepo, "@fixture/pkg", user); err != nil {
		t.Fatalf("same npm name in another repository was rejected: %v", err)
	}
	digest := sha512.Sum512([]byte("synthetic archive"))
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(digest[:])
	versionQuery := `INSERT INTO registry_npm_versions (npm_version_id, workspace_id, repository_id, package_id, version, version_identity, manifest, tarball_sha256, tarball_size, integrity, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, ` + p(6) + `, '{}', ` + p(7) + `, ` + p(8) + `, ` + p(9) + `, ` + p(10) + `, 'now')`
	versionID := uuid.NewString()
	if _, err := db.ExecContext(ctx, versionQuery, versionID, workspace, npmRepo, packageID, "1.0.0+first", "1.0.0", strings.Repeat("a", 64), 12, integrity, user); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		workspace, repository, version, identity, sha, integrity string
		size                                                     int
	}{
		{workspace, npmRepo, "1.0.0+second", "1.0.0", strings.Repeat("a", 64), integrity, 12},
		{otherWorkspace, otherRepo, "2.0.0", "2.0.0", strings.Repeat("a", 64), integrity, 12},
		{workspace, npmRepo, "2.0.0+build", "2.0.0+build", strings.Repeat("a", 64), integrity, 12},
		{workspace, npmRepo, "2.0.0", "2.0.0", strings.Repeat("A", 64), integrity, 12},
		{workspace, npmRepo, "2.0.0", "2.0.0", strings.Repeat("a", 64), "sha512-invalid", 12},
		{workspace, npmRepo, "2.0.0", "2.0.0", strings.Repeat("a", 64), integrity, 0},
	} {
		if _, err := db.ExecContext(ctx, versionQuery, uuid.NewString(), item.workspace, item.repository, packageID, item.version, item.identity, item.sha, item.size, item.integrity, user); err == nil {
			t.Fatal("invalid npm version insertion was accepted")
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_npm_packages SET name = 'changed' WHERE package_id = `+p(1), packageID); err == nil {
		t.Fatal("npm package identity was changed")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_npm_versions SET tarball_size = 13 WHERE npm_version_id = `+p(1), versionID); err == nil {
		t.Fatal("npm version content was changed")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM registry_npm_versions WHERE npm_version_id = `+p(1), versionID); err == nil {
		t.Fatal("npm version was deleted")
	}
	results := make(chan error, 2)
	for _, version := range []string{"3.0.0+first", "3.0.0+second"} {
		identity, err := npm.VersionIdentity(version)
		if err != nil {
			t.Fatal(err)
		}
		go func(version, identity string) {
			_, err := db.ExecContext(ctx, versionQuery, uuid.NewString(), workspace, npmRepo, packageID, version, identity, strings.Repeat("b", 64), 12, integrity, user)
			results <- err
		}(version, identity)
	}
	assertOneUniqueWinner(t, results)
}
