package migrations

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	"private-registry/internal/database"
)

// This experiment exercises the actual v17 SQLite schema. It does not install
// a migration or disable foreign keys on the application's connection pool.
func TestSQLiteRepositoryRebuildExperiment(t *testing.T) {
	for _, mode := range []string{"experiment-commit", "experiment-rollback", "migration-commit", "migration-rollback", "migration-guard"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
			delete(old, "sql/sqlite/000020_cargo_write_tokens.sql")
			delete(old, "sql/postgres/000020_cargo_write_tokens.sql")
			delete(old, "sql/sqlite/000021_cargo_reservations.sql")
			delete(old, "sql/postgres/000021_cargo_reservations.sql")
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
			if _, err := migrateWithFS(ctx, db, cfg, old); err != nil {
				t.Fatal(err)
			}
			user, workspace, repository, grant := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
			for _, statement := range []struct {
				query string
				args  []any
			}{
				{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (?, 'Synthetic', 'now', 'now')`, []any{user}},
				{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (?, 'fixture', 'Fixture', ?, 'now')`, []any{workspace, user}},
				{`INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, created_by, created_at, updated_at) VALUES (?, ?, 'owner', ?, 'now', 'now')`, []any{workspace, user, user}},
				{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format, visibility, logical_quota_bytes, logical_quota_revision, review_required, review_revision, go_namespace_mode, go_namespace_revision) VALUES (?, ?, 'modules', 'Modules', ?, 'now', 'now', 'go', 'listed', 12345, 4, 1, 7, 'private_prefixes', 3)`, []any{repository, workspace, user}},
				{`INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (?, ?, ?, ?, 'reader', ?, 'now')`, []any{grant, repository, workspace, user, user}},
				{`INSERT INTO registry_go_private_prefixes (workspace_id, repository_id, prefix) VALUES (?, ?, 'example.com/private')`, []any{workspace, repository}},
			} {
				if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(mode, "migration-") {
				var report Report
				if mode == "migration-guard" {
					engineFS, err := fs.Sub(embeddedMigrations, "sql/sqlite")
					if err != nil {
						t.Fatal(err)
					}
					provider, err := goose.NewProvider(goose.DialectSQLite3, db, engineFS, goose.WithDisableGlobalRegistry(true), goose.WithLogger(goose.NopLogger()))
					if err != nil {
						t.Fatal(err)
					}
					if _, err := provider.UpByOne(ctx); err == nil {
						t.Fatal("v18 executed without its dedicated connection")
					}
				} else if mode == "migration-rollback" {
					migrationPath := "sql/sqlite/000018_cargo_repository_format.sql"
					contents, err := fs.ReadFile(embeddedMigrations, migrationPath)
					if err != nil {
						t.Fatal(err)
					}
					const guard = "INSERT INTO registry_format_migration_guard SELECT count(*) FROM pragma_foreign_key_check;"
					if strings.Count(string(contents), guard) != 1 {
						t.Fatal("migration foreign key guard is missing")
					}
					broken := strings.Replace(string(contents), guard, "INSERT INTO registry_format_migration_guard VALUES (1);", 1)
					report, err = migrateWithFS(ctx, db, cfg, migrationFS(t, migrationPath, broken))
					if err == nil {
						t.Fatalf("injected migration failure unexpectedly succeeded: %+v", report)
					}
				} else {
					report, err = Migrate(ctx, db, cfg)
					if err != nil || report.CurrentVersion != 40 || len(report.AppliedVersions) != 23 || report.AppliedVersions[0] != 18 || report.AppliedVersions[1] != 19 || report.AppliedVersions[2] != 20 || report.AppliedVersions[3] != 21 || report.AppliedVersions[4] != 22 || report.AppliedVersions[5] != 23 || report.AppliedVersions[6] != 24 || report.AppliedVersions[7] != 25 || report.AppliedVersions[8] != 26 || report.AppliedVersions[9] != 27 || report.AppliedVersions[10] != 28 || report.AppliedVersions[11] != 29 || report.AppliedVersions[12] != 30 || report.AppliedVersions[13] != 31 || report.AppliedVersions[14] != 32 || report.AppliedVersions[15] != 33 || report.AppliedVersions[16] != 34 || report.AppliedVersions[17] != 35 || report.AppliedVersions[18] != 36 || report.AppliedVersions[19] != 37 || report.AppliedVersions[20] != 38 || report.AppliedVersions[21] != 39 || report.AppliedVersions[22] != 40 {
						t.Fatalf("v17 to v30 upgrade failed: %+v err=%v", report, err)
					}
					if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
						t.Fatalf("upgraded migration history failed verification: %v", err)
					}
				}
				conn, err := db.Conn(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				var applied int
				if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM goose_db_version WHERE version_id = 18 AND is_applied = 1`).Scan(&applied); err != nil {
					t.Fatal(err)
				}
				if (applied == 1) != (mode == "migration-commit") {
					t.Fatalf("migration version record inconsistent with outcome: mode=%s count=%d", mode, applied)
				}
				if mode == "migration-rollback" {
					var failed int
					if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM registry_migration_attempts WHERE version_id = 18 AND status = 'failed'`).Scan(&failed); err != nil || failed != 1 {
						t.Fatalf("failed migration attempt not recorded: count=%d err=%v", failed, err)
					}
				}
				assertRebuildState(t, ctx, conn, repository, workspace, user, mode != "migration-commit")
				assertPoolForeignKeys(t, ctx, db)
				return
			}
			var tableSQL string
			if err := db.QueryRowContext(ctx, `SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'registry_repositories'`).Scan(&tableSQL); err != nil {
				t.Fatal(err)
			}
			const oldCheck = `CHECK (format IN ('generic', 'go'))`
			if strings.Count(tableSQL, oldCheck) != 1 {
				t.Fatal("unexpected v17 repository format constraint")
			}
			replacement := strings.Replace(tableSQL, oldCheck, `CHECK (format IN ('generic', 'go', 'cargo'))`, 1)
			rows, err := db.QueryContext(ctx, `SELECT sql FROM sqlite_schema WHERE tbl_name = 'registry_repositories' AND type IN ('trigger', 'index') AND sql IS NOT NULL ORDER BY type, name`)
			if err != nil {
				t.Fatal(err)
			}
			var objects []string
			for rows.Next() {
				var object string
				if err := rows.Scan(&object); err != nil {
					t.Fatal(err)
				}
				objects = append(objects, object)
			}
			if err := errors.Join(rows.Err(), rows.Close()); err != nil {
				t.Fatal(err)
			}
			conn, err := db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.ExecContext(ctx, `PRAGMA legacy_alter_table=ON`); err != nil {
				t.Fatal(err)
			}
			tx, err := conn.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			statements := []string{`ALTER TABLE registry_repositories RENAME TO registry_repositories_old`, replacement, `INSERT INTO registry_repositories SELECT * FROM registry_repositories_old`, `DROP TABLE registry_repositories_old`}
			statements = append(statements, objects...)
			statements = append(statements, `CREATE TEMP TABLE synthetic_fk_guard (n INTEGER CHECK (n = 0))`, `INSERT INTO synthetic_fk_guard SELECT count(*) FROM pragma_foreign_key_check`, `DROP TABLE synthetic_fk_guard`)
			for _, query := range statements {
				if _, err := tx.ExecContext(ctx, query); err != nil {
					_ = tx.Rollback()
					t.Fatalf("synthetic SQLite rebuild failed: %v", err)
				}
			}
			if mode == "experiment-rollback" {
				err = tx.Rollback()
			} else {
				err = tx.Commit()
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.ExecContext(ctx, `PRAGMA legacy_alter_table=OFF`); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=ON`); err != nil {
				t.Fatal(err)
			}
			assertRebuildState(t, ctx, conn, repository, workspace, user, mode == "experiment-rollback")
		})
	}
}

func assertRebuildState(t *testing.T, ctx context.Context, conn *sql.Conn, repository, workspace, user string, aborted bool) {
	t.Helper()
	var grants, prefixes, violations, enabled int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM registry_repository_grants WHERE repository_id = ?`, repository).Scan(&grants); err != nil || grants != 1 {
		t.Fatalf("grant was not preserved: count=%d err=%v", grants, err)
	}
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM registry_go_private_prefixes WHERE repository_id = ?`, repository).Scan(&prefixes); err != nil || prefixes != 1 {
		t.Fatalf("Go namespace was not preserved: count=%d err=%v", prefixes, err)
	}
	var visibility, format, namespace string
	var quota, quotaRevision, reviewRequired, reviewRevision, namespaceRevision int64
	if err := conn.QueryRowContext(ctx, `SELECT visibility, format, logical_quota_bytes, logical_quota_revision, review_required, review_revision, go_namespace_mode, go_namespace_revision FROM registry_repositories WHERE repository_id = ?`, repository).Scan(&visibility, &format, &quota, &quotaRevision, &reviewRequired, &reviewRevision, &namespace, &namespaceRevision); err != nil || visibility != "listed" || format != "go" || quota != 12345 || quotaRevision != 4 || reviewRequired != 1 || reviewRevision != 7 || namespace != "private_prefixes" || namespaceRevision != 3 {
		t.Fatalf("repository settings not preserved: err=%v", err)
	}
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM pragma_foreign_key_check`).Scan(&violations); err != nil || violations != 0 {
		t.Fatalf("foreign keys invalid: count=%d err=%v", violations, err)
	}
	if err := conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&enabled); err != nil || enabled != 1 {
		t.Fatalf("foreign keys disabled: value=%d err=%v", enabled, err)
	}
	var stale int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE sql LIKE '%registry_repositories_before_format18%'`).Scan(&stale); err != nil || stale != 0 {
		t.Fatalf("stale repository references: count=%d err=%v", stale, err)
	}
	if _, err := conn.ExecContext(ctx, `UPDATE registry_repositories SET format = 'generic' WHERE repository_id = ?`, repository); err == nil {
		t.Fatal("existing repository format became mutable")
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO registry_generic_artifact_versions (artifact_version_id, workspace_id, repository_id, collection_name, version_label, status, created_by, created_at) VALUES (?, ?, ?, 'fixture', 'v1', 'receiving', ?, 'now')`, uuid.NewString(), workspace, repository, user); err == nil || !strings.Contains(err.Error(), "generic artifacts require a generic repository") {
		t.Fatalf("generic format guard was not preserved: %v", err)
	}
	_, err := conn.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'cargo', 'Cargo', ?, 'now', 'now', 'cargo')`, uuid.NewString(), workspace, user)
	if (err != nil) != aborted {
		t.Fatalf("unexpected Cargo insert after rollback=%t: %v", aborted, err)
	}
}

func assertPoolForeignKeys(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var connections []*sql.Conn
	defer func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	}()
	// One connection is already held by the caller; inspect the remaining pool.
	for range 3 {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		var foreignKeys, legacy int
		if err := conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil || foreignKeys != 1 {
			t.Fatalf("normal pool lost foreign key enforcement: value=%d err=%v", foreignKeys, err)
		}
		if err := conn.QueryRowContext(ctx, `PRAGMA legacy_alter_table`).Scan(&legacy); err != nil || legacy != 0 {
			t.Fatalf("normal pool inherited legacy migration settings: value=%d err=%v", legacy, err)
		}
	}
}
