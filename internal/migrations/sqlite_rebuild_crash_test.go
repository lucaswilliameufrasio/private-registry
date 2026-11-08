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
	delete(old, "sql/sqlite/000018_cargo_repository_format.sql")
	delete(old, "sql/postgres/000018_cargo_repository_format.sql")
	delete(old, "sql/sqlite/000019_cargo_catalog.sql")
	delete(old, "sql/postgres/000019_cargo_catalog.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 17 {
		t.Fatalf("prepare v17 fixture: %+v err=%v", report, err)
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
	marker := uuid.NewString()
	if err := os.WriteFile(filepath.Join(cfg.DataDir, ".synthetic-rebuild-fixture"), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, executable, "-test.run=^TestSQLiteRebuildCrashHelper$")
	child.Env = []string{"REGISTRY_SYNTHETIC_CRASH_DB=" + cfg.DatabaseDSN, "REGISTRY_SYNTHETIC_CRASH_MARKER=" + marker, "TMPDIR=" + os.TempDir()}
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
		{`SELECT count(*) FROM sqlite_schema WHERE name = 'registry_repositories_before_format18'`, nil, &stale},
		{`SELECT count(*) FROM pragma_foreign_key_check`, nil, &violations},
		{`SELECT count(*) FROM goose_db_version WHERE version_id = 18 AND is_applied = 1`, nil, &applied},
	} {
		if err := db.QueryRowContext(ctx, item.query, item.args...).Scan(item.value); err != nil {
			t.Fatal(err)
		}
	}
	if repositories != 1 || prefixes != 1 || stale != 0 || violations != 0 || applied != 0 {
		t.Fatalf("synthetic crash changed source: repository=%d prefixes=%d stale=%d violations=%d applied=%d", repositories, prefixes, stale, violations, applied)
	}
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
	if _, err := tx.ExecContext(ctx, `ALTER TABLE registry_repositories RENAME TO registry_repositories_before_format18`); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(os.Stdout, "transaction-open"); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}
