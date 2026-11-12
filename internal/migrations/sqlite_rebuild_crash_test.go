package migrations

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
)

// This checks SQLite rollback after a subprocess dies inside a synthetic
// rebuild transaction. It does not simulate every interruption of Migrate.
func TestSQLiteRebuildProcessCrashRollsBack(t *testing.T) {
	for _, version := range []int{18, 25} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			exerciseSQLiteRebuildProcessCrash(t, version)
		})
	}
}

func exerciseSQLiteRebuildProcessCrash(t *testing.T, version int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cfg := sqliteConfig(t)
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
	if version == 18 {
		for _, engine := range []string{"sqlite", "postgres"} {
			for _, name := range []string{"000018_cargo_repository_format.sql", "000019_cargo_catalog.sql", "000020_cargo_write_tokens.sql", "000021_cargo_reservations.sql", "000022_cargo_receipts.sql", "000023_cargo_review.sql", "000024_cargo_publications.sql"} {
				delete(old, "sql/"+engine+"/"+name)
			}
		}
	}
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
	delete(old, "sql/sqlite/000041_oci_repository_format.sql")
	delete(old, "sql/postgres/000041_oci_repository_format.sql")
	delete(old, "sql/sqlite/000042_oci_registry.sql")
	delete(old, "sql/postgres/000042_oci_registry.sql")
	delete(old, "sql/sqlite/000043_oci_policies.sql")
	delete(old, "sql/postgres/000043_oci_policies.sql")
	delete(old, "sql/sqlite/000044_invitations_and_oci_review.sql")
	delete(old, "sql/postgres/000044_invitations_and_oci_review.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != int64(version-1) {
		t.Fatalf("prepare pre-rebuild fixture: %+v err=%v", report, err)
	}
	user, workspace, repository := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, item := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (?, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (?, 'fixture', 'Fixture', ?, 'now')`, []any{workspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'modules', 'Modules', ?, 'now', 'now', 'go')`, []any{repository, workspace, user}},
		{`INSERT INTO registry_go_private_prefixes (workspace_id, repository_id, prefix) VALUES (?, ?, 'example.com/private')`, []any{workspace, repository}},
	} {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	var cargoPackage string
	if version == 25 {
		cargoRepo := uuid.NewString()
		cargoPackage = uuid.NewString()
		if _, err := db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'cargo', 'Cargo', ?, 'now', 'now', 'cargo')`, cargoRepo, workspace, user); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO registry_cargo_packages (package_id, workspace_id, repository_id, name, name_identity, created_by, created_at) VALUES (?, ?, ?, 'fixture', 'fixture', ?, 'now')`, cargoPackage, workspace, cargoRepo, user); err != nil {
			t.Fatal(err)
		}
	}
	marker := uuid.NewString()
	if err := os.WriteFile(filepath.Join(cfg.DataDir, ".synthetic-rebuild-fixture"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, executable, "-test.run=^TestSQLiteRebuildCrashHelper$")
	child.Env = []string{"REGISTRY_SYNTHETIC_CRASH_DB=" + cfg.DatabaseDSN, "REGISTRY_SYNTHETIC_CRASH_MARKER=" + marker, fmt.Sprintf("REGISTRY_SYNTHETIC_CRASH_VERSION=%d", version), "TMPDIR=" + os.TempDir()}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "transaction-open\n" {
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatalf("synthetic child did not reach rebuild: %v", err)
	}
	if err := child.Process.Kill(); err != nil {
		_ = child.Wait()
		t.Fatal(err)
	}
	_ = stdin.Close()
	if err := child.Wait(); err == nil {
		t.Fatal("synthetic child unexpectedly exited successfully")
	}
	var repositories, prefixes, stale, violations, applied int
	for _, item := range []struct {
		query string
		args  []any
		value *int
	}{
		{`SELECT count(*) FROM registry_repositories WHERE repository_id = ? AND format = 'go'`, []any{repository}, &repositories},
		{`SELECT count(*) FROM registry_go_private_prefixes WHERE repository_id = ?`, []any{repository}, &prefixes},
		{`SELECT count(*) FROM sqlite_schema WHERE name = ?`, []any{fmt.Sprintf("registry_repositories_before_format%d", version)}, &stale},
		{`SELECT count(*) FROM pragma_foreign_key_check`, nil, &violations},
		{`SELECT count(*) FROM goose_db_version WHERE version_id = ? AND is_applied = 1`, []any{version}, &applied},
	} {
		if err := db.QueryRowContext(ctx, item.query, item.args...).Scan(item.value); err != nil {
			t.Fatal(err)
		}
	}
	if repositories != 1 || prefixes != 1 || stale != 0 || violations != 0 || applied != 0 {
		t.Fatalf("synthetic crash changed source: repository=%d prefixes=%d stale=%d violations=%d applied=%d", repositories, prefixes, stale, violations, applied)
	}
	if version == 25 {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_cargo_packages WHERE package_id = ?`, cargoPackage).Scan(&count); err != nil || count != 1 {
			t.Fatalf("synthetic crash changed Cargo reference: count=%d err=%v", count, err)
		}
	}
	report, err := Migrate(ctx, db, cfg)
	if err != nil || report.CurrentVersion != 44 {
		t.Fatalf("migration did not resume after synthetic crash: %+v err=%v", report, err)
	}
	if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
		t.Fatalf("resumed migration history is invalid: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_go_private_prefixes WHERE repository_id = ?`, repository).Scan(&prefixes); err != nil || prefixes != 1 {
		t.Fatalf("resumed migration lost Go reference: count=%d err=%v", prefixes, err)
	}
	if version == 25 {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_cargo_packages WHERE package_id = ?`, cargoPackage).Scan(&count); err != nil || count != 1 {
			t.Fatalf("resumed migration lost Cargo reference: count=%d err=%v", count, err)
		}
	}
	assertPoolForeignKeys(t, ctx, db)
}

func TestSQLiteRebuildCrashHelper(t *testing.T) {
	path := os.Getenv("REGISTRY_SYNTHETIC_CRASH_DB")
	if path == "" {
		return
	}
	relative, err := filepath.Rel(os.TempDir(), path)
	if err != nil || !filepath.IsAbs(path) || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.Base(path) != "registry.sqlite" {
		t.Fatal("synthetic crash database is outside the test temporary directory")
	}
	marker, err := os.ReadFile(filepath.Join(filepath.Dir(path), ".synthetic-rebuild-fixture"))
	if err != nil || string(marker) == "" || string(marker) != os.Getenv("REGISTRY_SYNTHETIC_CRASH_MARKER") {
		t.Fatal("synthetic crash fixture marker is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg := config.Config{DataDir: filepath.Dir(path), DatabaseDriver: config.SQLite, DatabaseDSN: path, DatabaseMaxOpenConns: 1}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, query := range []string{`PRAGMA foreign_keys=OFF`, `PRAGMA legacy_alter_table=ON`} {
		if _, err := conn.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var rename string
	switch os.Getenv("REGISTRY_SYNTHETIC_CRASH_VERSION") {
	case "18":
		rename = `ALTER TABLE registry_repositories RENAME TO registry_repositories_before_format18`
	case "25":
		rename = `ALTER TABLE registry_repositories RENAME TO registry_repositories_before_format25`
	default:
		t.Fatal("synthetic crash migration version is invalid")
	}
	if _, err := tx.ExecContext(ctx, rename); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(os.Stdout, "transaction-open"); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}
