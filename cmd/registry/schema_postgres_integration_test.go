//go:build integration

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/testinfra"
)

func TestServeSchemaVerificationPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	fixture, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Error(err)
		}
	})
	cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 2}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := verifyServeSchema(ctx, db, config.Postgres); err == nil {
		t.Fatal("unmigrated PostgreSQL database was accepted")
	}
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	if err := verifyServeSchema(ctx, db, config.Postgres); err != nil {
		t.Fatal("current PostgreSQL schema rejected:", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_migration_checksums SET checksum = $1 WHERE version_id = 16`, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if err := verifyServeSchema(ctx, db, config.Postgres); err == nil {
		t.Fatal("altered PostgreSQL checksum was accepted")
	}
}
