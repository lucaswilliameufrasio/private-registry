//go:build integration

package cargo_test

import (
	"context"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/testinfra"
)

func TestPostgresCargoReservations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Error(err)
		}
	})
	cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	exerciseReservations(t, ctx, db, config.Postgres)
	exerciseCargoReceipt(t, ctx, db, config.Postgres, t.TempDir())
}
