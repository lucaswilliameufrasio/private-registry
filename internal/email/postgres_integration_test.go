//go:build integration && linux

package email_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/jobs"
	"private-registry/internal/migrations"
	"private-registry/internal/secrets"
	"private-registry/internal/testinfra"
)

func TestPostgresFailuresAreRecordedListedAndResent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	postgres, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := postgres.Stop(); err != nil {
			t.Errorf("stop owned PostgreSQL fixture: %v", err)
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
	root := t.TempDir()
	dataDir, keyDir := filepath.Join(root, "data"), filepath.Join(root, "keys")
	for _, dir := range []string{dataDir, keyDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(keyDir, "master.key")
	if err := secrets.InitializeMasterKey(keyPath, dataDir); err != nil {
		t.Fatal(err)
	}
	key, err := secrets.LoadMasterKeyFile(keyPath, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	queue, err := jobs.New(db, config.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	ExerciseFailuresAndResend(t, db, config.Postgres, queue, &key)
}
