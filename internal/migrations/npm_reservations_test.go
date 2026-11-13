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

func TestSQLiteNPMReservationMigration(t *testing.T) {
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
			exerciseNPMReservationMigration(t, ctx, db, cfg, fail)
		})
	}
}

func exerciseNPMReservationMigration(t *testing.T, ctx context.Context, db *sql.DB, cfg config.Config, fail bool) {
	t.Helper()
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
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
	delete(old, "sql/sqlite/000045_service_accounts_recovery_passkeys.sql")
	delete(old, "sql/postgres/000045_service_accounts_recovery_passkeys.sql")
	delete(old, "sql/sqlite/000046_email_delivery.sql")
	delete(old, "sql/postgres/000046_email_delivery.sql")
	delete(old, "sql/sqlite/000047_email_failures.sql")
	delete(old, "sql/postgres/000047_email_failures.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 27 {
		t.Fatalf("prepare v27 fixture: %+v err=%v", report, err)
	}
	if !fail {
		report, err := Migrate(ctx, db, cfg)
		if err != nil || report.CurrentVersion != 47 || len(report.AppliedVersions) != 20 || report.AppliedVersions[0] != 28 || report.AppliedVersions[1] != 29 || report.AppliedVersions[2] != 30 || report.AppliedVersions[3] != 31 || report.AppliedVersions[4] != 32 || report.AppliedVersions[5] != 33 || report.AppliedVersions[6] != 34 || report.AppliedVersions[7] != 35 || report.AppliedVersions[8] != 36 || report.AppliedVersions[9] != 37 || report.AppliedVersions[10] != 38 || report.AppliedVersions[11] != 39 || report.AppliedVersions[12] != 40 || report.AppliedVersions[13] != 41 || report.AppliedVersions[14] != 42 || report.AppliedVersions[15] != 43 || report.AppliedVersions[16] != 44 || report.AppliedVersions[17] != 45 || report.AppliedVersions[18] != 46 || report.AppliedVersions[19] != 47 {
			t.Fatalf("v28–v30 upgrade failed: %+v err=%v", report, err)
		}
		if err := VerifyCurrent(ctx, db, cfg.DatabaseDriver, report.InstallationID); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := "sql/sqlite/000028_npm_reservations.sql"
	query := `SELECT count(*) FROM sqlite_schema WHERE name = 'registry_npm_reservations'`
	if cfg.DatabaseDriver == config.Postgres {
		path = "sql/postgres/000028_npm_reservations.sql"
		query = `SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'registry_npm_reservations'`
	}
	contents, err := fs.ReadFile(embeddedMigrations, path)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(contents), "-- +goose Down", "INSERT INTO nonexistent_npm_failure_fixture VALUES (1);\n-- +goose Down", 1)
	if broken == string(contents) {
		t.Fatal("failed to inject v28 migration failure")
	}
	if _, err := migrateWithFS(ctx, db, cfg, migrationFS(t, path, broken)); err == nil {
		t.Fatal("injected npm reservation migration failure succeeded")
	}
	var count int
	if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed v28 migration left reservation table: count=%d err=%v", count, err)
	}
	if _, err := Migrate(ctx, db, cfg); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("changed migration source was not rejected: %v", err)
	}
}
