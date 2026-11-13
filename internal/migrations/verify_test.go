package migrations

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
)

func TestVerifyCurrentDoesNotMigrateAndRejectsChangedHistory(t *testing.T) {
	cfg := sqliteConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDatabase(t, db))
	if err := VerifyCurrent(ctx, db, config.SQLite, uuid.NewString()); err == nil {
		t.Fatal("empty database was accepted without migrations")
	}
	report, err := Migrate(ctx, db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCurrent(ctx, db, config.SQLite, report.InstallationID); err != nil {
		t.Fatal("verify migrated fixture:", err)
	}
	if err := VerifyCurrent(ctx, db, config.SQLite, uuid.NewString()); err == nil {
		t.Fatal("wrong installation identity accepted")
	}
	if err := VerifyCurrent(context.Background(), db, config.SQLite, report.InstallationID); err == nil {
		t.Fatal("verification without deadline accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_migration_checksums SET checksum = ? WHERE version_id = 1`, "0000000000000000000000000000000000000000000000000000000000000000"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCurrent(ctx, db, config.SQLite, report.InstallationID); err == nil {
		t.Fatal("changed migration checksum accepted")
	}
}
