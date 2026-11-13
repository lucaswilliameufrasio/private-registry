package migrations

import (
	"context"
	"database/sql"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
)

func TestSQLitePubNativeUploadMigration(t *testing.T) {
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
			exercisePubNativeUploadMigration(t, ctx, db, cfg, fail)
		})
	}
}

func exercisePubNativeUploadMigration(t *testing.T, ctx context.Context, db *sql.DB, cfg config.Config, fail bool) {
	t.Helper()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
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
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 39 {
		t.Fatalf("prepare v39 fixture: %+v err=%v", report, err)
	}
	if !fail {
		report, err := Migrate(ctx, db, cfg)
		if err != nil || report.CurrentVersion != 47 || len(report.AppliedVersions) != 8 || report.AppliedVersions[0] != 40 || report.AppliedVersions[1] != 41 || report.AppliedVersions[2] != 42 || report.AppliedVersions[3] != 43 || report.AppliedVersions[4] != 44 || report.AppliedVersions[5] != 45 || report.AppliedVersions[6] != 46 || report.AppliedVersions[7] != 47 {
			t.Fatalf("v40 upgrade failed: %+v err=%v", report, err)
		}
		if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := "sql/sqlite/000040_pub_native_uploads.sql"
	query := `SELECT count(*) FROM sqlite_schema WHERE name = 'registry_pub_native_uploads'`
	if cfg.DatabaseDriver == config.Postgres {
		path = "sql/postgres/000040_pub_native_uploads.sql"
		query = `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'registry_pub_native_uploads'`
	}
	contents, err := fs.ReadFile(embeddedMigrations, path)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(contents), "-- +goose Down", "INSERT INTO nonexistent_pub_reservation_failure_fixture VALUES (1);\n-- +goose Down", 1)
	if broken == string(contents) {
		t.Fatal("failed to inject Pub native upload migration failure")
	}
	if _, err := migrateWithFS(ctx, db, cfg, migrationFS(t, path, broken)); err == nil {
		t.Fatal("injected Pub native upload migration failure succeeded")
	}
	var count int
	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed Pub native upload migration did not preserve table: count=%d err=%v", count, err)
	}
	if _, err := Migrate(ctx, db, cfg); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("changed Pub native upload migration source was not rejected: %v", err)
	}
}
