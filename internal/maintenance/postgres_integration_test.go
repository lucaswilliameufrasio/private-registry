//go:build integration

package maintenance

import (
	"context"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/testinfra"
)

func TestPostgresUploadExpirationRunsAndSurvivesWorkerRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	postgres, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal("start isolated PostgreSQL:", err)
	}
	t.Cleanup(func() {
		if err := postgres.Stop(); err != nil {
			t.Error("stop PostgreSQL:", err)
		}
	})
	cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: postgres.DSN(), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	exerciseUploadExpiration(t, db, config.Postgres, t.TempDir())
}
