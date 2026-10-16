package main

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
)

func TestRunMigrateBootstrapsLocalSQLiteInstallation(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "registry-data")
	databasePath := filepath.Join(dataDir, "registry.sqlite")
	t.Setenv("REGISTRY_DATA_DIR", dataDir)
	t.Setenv("REGISTRY_DATABASE_DRIVER", "sqlite")
	t.Setenv("REGISTRY_DATABASE_DSN", databasePath)
	t.Setenv("REGISTRY_DATABASE_MAX_OPEN_CONNS", "4")

	var logOutput bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logOutput, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	if err := run(ctx, []string{"migrate"}, logger); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logOutput.String(), "database migrations complete") {
		t.Fatalf("migration completion was not logged: %q", logOutput.String())
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	var installationCount int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM registry_installation").Scan(&installationCount); err != nil {
		t.Fatal(err)
	}
	if installationCount != 1 {
		t.Fatalf("expected one installation row, got %d", installationCount)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	err := run(context.Background(), []string{"publish"}, slog.Default())
	if err == nil || err.Error() != "usage: registry {serve|migrate|bootstrap-admin}" {
		t.Fatalf("unexpected unknown-command result: %v", err)
	}
}
