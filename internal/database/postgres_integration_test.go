//go:build integration

package database

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/testinfra"
)

func TestOpenPostgresUsesRealLocalDatabase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	fixture, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Errorf("stop owned PostgreSQL fixture: %v", err)
		}
	})

	cfg := config.Config{
		DatabaseDriver:       config.Postgres,
		DatabaseDSN:          fixture.DSN(),
		DatabaseMaxOpenConns: 4,
	}
	db, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	table := "foundation_" + hex.EncodeToString(suffix[:])
	if _, err := db.ExecContext(ctx, "CREATE TABLE "+table+" (value TEXT NOT NULL)"); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO "+table+" (value) VALUES ($1)", "survives reconnect"); err != nil {
		_, _ = db.ExecContext(ctx, "DROP TABLE "+table)
		_ = db.Close()
		t.Fatal(err)
	}
	var version string
	if err := db.QueryRowContext(ctx, "SHOW server_version").Scan(&version); err != nil {
		_, _ = db.ExecContext(ctx, "DROP TABLE "+table)
		_ = db.Close()
		t.Fatal(err)
	}
	if !strings.HasPrefix(version, "18.") {
		_, _ = db.ExecContext(ctx, "DROP TABLE "+table)
		_ = db.Close()
		t.Fatalf("unexpected PostgreSQL fixture version: %s", version)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close PostgreSQL connection: %v", err)
		}
	}()
	var value string
	if err := db.QueryRowContext(ctx, "SELECT value FROM "+table).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "survives reconnect" {
		t.Fatalf("PostgreSQL did not preserve committed data: %q", value)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE "+table); err != nil {
		t.Fatal(err)
	}
}
