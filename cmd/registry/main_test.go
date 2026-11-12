package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/secrets"
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
	if err == nil || err.Error() != "usage: registry {serve|migrate|bootstrap-admin|init-master-key|restore-database|migrate-objects|collect-objects [--apply]}" {
		t.Fatalf("unexpected unknown-command result: %v", err)
	}
}

func TestServeRejectsIncompleteRecoveryBeforeOpeningDatabase(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "recovery")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dataDir, "RECOVERY_INCOMPLETE")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(dataDir, "registry.sqlite")
	t.Setenv("REGISTRY_DATA_DIR", dataDir)
	t.Setenv("REGISTRY_DATABASE_DRIVER", "sqlite")
	t.Setenv("REGISTRY_DATABASE_DSN", databasePath)
	t.Setenv("REGISTRY_DATABASE_MAX_OPEN_CONNS", "4")
	err := run(context.Background(), []string{"serve"}, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "incomplete recovery") {
		t.Fatalf("serve incomplete recovery = %v", err)
	}
	if _, err := os.Stat(databasePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("serve touched recovery database: %v", err)
	}
	otherData := filepath.Join(t.TempDir(), "other-data")
	t.Setenv("REGISTRY_DATA_DIR", otherData)
	err = run(context.Background(), []string{"serve"}, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "incomplete recovery") {
		t.Fatalf("serve recovered SQLite under another data directory = %v", err)
	}
}

func TestServeSchemaVerificationIsReadOnlyAndFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "registry-data")
	cfg := config.Config{DataDir: root, DatabaseDriver: config.SQLite, DatabaseDSN: filepath.Join(root, "registry.sqlite"), DatabaseMaxOpenConns: 2}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := verifyServeSchema(ctx, db, config.SQLite); err == nil {
		t.Fatal("serve schema verification accepted an unmigrated database")
	}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'goose_db_version')`).Scan(&exists); err != nil || exists {
		t.Fatalf("serve schema verification performed migrations: exists=%t err=%v", exists, err)
	}
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	if err := verifyServeSchema(ctx, db, config.SQLite); err != nil {
		t.Fatal("verify current schema:", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_migration_checksums SET checksum = ? WHERE version_id = 16`, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if err := verifyServeSchema(ctx, db, config.SQLite); err == nil {
		t.Fatal("serve schema verification accepted a changed migration checksum")
	}
}

func TestServeRefusesUnmigratedSchemaBeforeOpeningListener(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "registry-data")
	t.Setenv("REGISTRY_DATA_DIR", dataDir)
	t.Setenv("REGISTRY_DATABASE_DRIVER", "sqlite")
	t.Setenv("REGISTRY_DATABASE_DSN", filepath.Join(dataDir, "registry.sqlite"))
	t.Setenv("REGISTRY_MASTER_KEY_FILE", filepath.Join(root, "missing-key"))
	t.Setenv("REGISTRY_CANONICAL_ORIGIN", "https://registry.example")
	t.Setenv("REGISTRY_ASSET_ORIGIN", "https://assets.example")
	t.Setenv("REGISTRY_TRUSTED_PROXIES", "127.0.0.1")
	t.Setenv("REGISTRY_LISTEN_ADDRESS", "127.0.0.1:34567")
	err := run(context.Background(), []string{"serve"}, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "schema is not ready") {
		t.Fatalf("serve accepted unmigrated schema or proceeded to key/listener: %v", err)
	}
}

func TestRunInitMasterKeyCreatesPrivateKeyWithoutDatabase(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local master key files are supported only on Linux")
	}
	root := t.TempDir()
	keyDirectory := filepath.Join(root, "keys")
	if err := os.Mkdir(keyDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDirectory, "registry-master.key")
	t.Setenv("REGISTRY_DATA_DIR", filepath.Join(root, "data-does-not-exist"))
	t.Setenv("REGISTRY_MASTER_KEY_FILE", keyPath)

	var logOutput bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logOutput, nil))
	if err := run(context.Background(), []string{"init-master-key"}, logger); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logOutput.String(), "local master key initialized") {
		t.Fatalf("initialization result was not logged: %q", logOutput.String())
	}
	if strings.Contains(logOutput.String(), keyPath) {
		t.Fatalf("initialization log exposed the key file path: %q", logOutput.String())
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected master key permissions: %04o", info.Mode().Perm())
	}

	masterKey, err := secrets.LoadMasterKeyFile(keyPath, filepath.Join(root, "data-does-not-exist"))
	if err != nil {
		t.Fatal(err)
	}
	masterKey.Destroy()

	if err := run(context.Background(), []string{"init-master-key"}, logger); !errors.Is(err, secrets.ErrMasterKeyAlreadyExists) {
		t.Fatalf("expected existing key to be preserved, got %v", err)
	}
}
