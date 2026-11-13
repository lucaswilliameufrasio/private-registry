package migrations

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/database"
)

func TestSQLiteCargoCatalogConstraints(t *testing.T) {
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
	exerciseCargoCatalogConstraints(t, ctx, db, config.SQLite)
}

func exerciseCargoCatalogConstraints(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver) {
	t.Helper()
	p := func(n int) string { return bind(driver, n) }
	user, workspace, otherWorkspace, cargoRepo, otherRepo, goRepo := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (` + p(1) + `, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (` + p(1) + `, 'cargo-one', 'Cargo one', ` + p(2) + `, 'now')`, []any{workspace, user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (` + p(1) + `, 'cargo-two', 'Cargo two', ` + p(2) + `, 'now')`, []any{otherWorkspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'cargo', 'Cargo', ` + p(3) + `, 'now', 'now', 'cargo')`, []any{cargoRepo, workspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'cargo', 'Cargo', ` + p(3) + `, 'now', 'now', 'cargo')`, []any{otherRepo, otherWorkspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'go', 'Go', ` + p(3) + `, 'now', 'now', 'go')`, []any{goRepo, workspace, user}},
	}
	for _, item := range statements {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	packageQuery := `INSERT INTO registry_cargo_packages (package_id, workspace_id, repository_id, name, name_identity, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, ` + p(6) + `, 'now')`
	packageID := uuid.NewString()
	if _, err := db.ExecContext(ctx, packageQuery, packageID, workspace, cargoRepo, "my-crate", "my_crate", user); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name      string
		workspace string
		repo      string
		identity  string
	}{
		{"duplicate canonical package", workspace, cargoRepo, "my_crate"},
		{"cross workspace", otherWorkspace, cargoRepo, "other"},
		{"Go format", workspace, goRepo, "other"},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, packageQuery, uuid.NewString(), item.workspace, item.repo, "other", item.identity, user); err == nil {
				t.Fatal("invalid Cargo package insertion was accepted")
			}
		})
	}
	if _, err := db.ExecContext(ctx, packageQuery, uuid.NewString(), otherWorkspace, otherRepo, "my_crate", "my_crate", user); err != nil {
		t.Fatalf("same package identity in another repository was rejected: %v", err)
	}
	versionQuery := `INSERT INTO registry_cargo_versions (cargo_version_id, workspace_id, repository_id, package_id, version, version_identity, index_entry, archive_sha256, archive_size, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, ` + p(6) + `, '{}', ` + p(7) + `, 12, ` + p(8) + `, 'now')`
	versionID := uuid.NewString()
	if _, err := db.ExecContext(ctx, versionQuery, versionID, workspace, cargoRepo, packageID, "1.0.0+build", "1.0.0", strings.Repeat("a", 64), user); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, versionQuery, uuid.NewString(), workspace, cargoRepo, packageID, "1.0.0+other", "1.0.0", strings.Repeat("b", 64), user); err == nil {
		t.Fatal("duplicate Cargo version identity accepted")
	}
	if _, err := db.ExecContext(ctx, versionQuery, uuid.NewString(), otherWorkspace, otherRepo, packageID, "2.0.0", "2.0.0", strings.Repeat("b", 64), user); err == nil {
		t.Fatal("cross-tenant Cargo version accepted")
	}
	if _, err := db.ExecContext(ctx, versionQuery, uuid.NewString(), workspace, cargoRepo, packageID, "2.0.0", "2.0.0", strings.Repeat("A", 64), user); err == nil {
		t.Fatal("invalid digest accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_packages SET name = 'changed' WHERE package_id = `+p(1), packageID); err == nil {
		t.Fatal("Cargo package identity was changed")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_versions SET archive_sha256 = `+p(1)+` WHERE cargo_version_id = `+p(2), strings.Repeat("c", 64), versionID); err == nil {
		t.Fatal("Cargo version content was changed")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM registry_cargo_versions WHERE cargo_version_id = `+p(1), versionID); err == nil {
		t.Fatal("Cargo version was deleted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_versions SET yanked = 1 WHERE cargo_version_id = `+p(1), versionID); err != nil {
		t.Fatalf("Cargo yank state could not be updated: %v", err)
	}
	var yanked int
	if err := db.QueryRowContext(ctx, `SELECT yanked FROM registry_cargo_versions WHERE cargo_version_id = `+p(1), versionID).Scan(&yanked); err != nil || yanked != 1 {
		t.Fatalf("Cargo yank state not retained: value=%d err=%v", yanked, err)
	}
	racePackageIdentity(t, ctx, db, packageQuery, workspace, cargoRepo, user)
	raceVersionIdentity(t, ctx, db, versionQuery, workspace, cargoRepo, packageID, user)
}

func racePackageIdentity(t *testing.T, ctx context.Context, db *sql.DB, query, workspace, repository, user string) {
	t.Helper()
	results := make(chan error, 2)
	for _, name := range []string{"race-crate", "race_crate"} {
		identity, err := cargo.NameIdentity(name)
		if err != nil {
			t.Fatal(err)
		}
		go func(name, identity string) {
			_, err := db.ExecContext(ctx, query, uuid.NewString(), workspace, repository, name, identity, user)
			results <- err
		}(name, identity)
	}
	assertOneUniqueWinner(t, results)
}

func raceVersionIdentity(t *testing.T, ctx context.Context, db *sql.DB, query, workspace, repository, packageID, user string) {
	t.Helper()
	results := make(chan error, 2)
	for _, version := range []string{"2.0.0+first", "2.0.0+second"} {
		identity, err := cargo.VersionIdentity(version)
		if err != nil {
			t.Fatal(err)
		}
		go func(version, identity string) {
			_, err := db.ExecContext(ctx, query, uuid.NewString(), workspace, repository, packageID, version, identity, strings.Repeat("d", 64), user)
			results <- err
		}(version, identity)
	}
	assertOneUniqueWinner(t, results)
}

func assertOneUniqueWinner(t *testing.T, results <-chan error) {
	t.Helper()
	var succeeded, conflicts int
	for range 2 {
		err := <-results
		if err == nil {
			succeeded++
			continue
		}
		if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "duplicate key value") {
			conflicts++
			continue
		}
		t.Fatalf("unexpected concurrent catalog error: %v", err)
	}
	if succeeded != 1 || conflicts != 1 {
		t.Fatalf("concurrent catalog identity winners=%d conflicts=%d", succeeded, conflicts)
	}
}
