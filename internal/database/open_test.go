package database

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"private-registry/internal/config"
)

func TestOpenSQLiteUsesDurablePrivateDatabaseAndRequiredPragmas(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "registry-data")
	dsn := filepath.Join(dataDir, "registry.sqlite")
	cfg := config.Config{
		DataDir:              dataDir,
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          dsn,
		DatabaseMaxOpenConns: 4,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	db, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		query string
		want  string
	}{
		{name: "journal mode", query: "PRAGMA journal_mode", want: "wal"},
		{name: "foreign keys", query: "PRAGMA foreign_keys", want: "1"},
		{name: "synchronous", query: "PRAGMA synchronous", want: "2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got string
			if err := db.QueryRowContext(ctx, test.query).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("unexpected pragma value: got %q, want %q", got, test.want)
			}
		})
	}

	if _, err := db.ExecContext(ctx, "CREATE TABLE persisted (value TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO persisted (value) VALUES (?)", "survives restart"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	directoryInfo, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("unexpected SQLite directory permissions: %04o", got)
	}
	fileInfo, err := os.Stat(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("unexpected SQLite file permissions: %04o", got)
	}

	reopened, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened database: %v", err)
		}
	})
	var value string
	if err := reopened.QueryRowContext(ctx, "SELECT value FROM persisted").Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "survives restart" {
		t.Fatalf("database data did not survive reopen: %q", value)
	}
}

func TestOpenRejectsUnsafeExistingSQLiteFile(t *testing.T) {
	dataDir := t.TempDir()
	dsn := filepath.Join(dataDir, "registry.sqlite")
	if err := os.WriteFile(dsn, []byte("synthetic"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		DataDir:              dataDir,
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          dsn,
		DatabaseMaxOpenConns: 4,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := Open(ctx, cfg); err == nil {
		t.Fatal("expected SQLite database with broad permissions to be rejected")
	}
}

func TestOpenRejectsCanceledContextBeforeCreatingSQLiteFile(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "registry-data")
	cfg := config.Config{
		DataDir:              dataDir,
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          filepath.Join(dataDir, "registry.sqlite"),
		DatabaseMaxOpenConns: 4,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := Open(ctx, cfg); err == nil {
		t.Fatal("expected canceled context to fail")
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("canceled open created a data directory: %v", err)
	}
}
