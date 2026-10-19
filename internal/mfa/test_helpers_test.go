//go:build linux

package mfa

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/secrets"
)

type sqliteFixture struct {
	db       *sql.DB
	service  *Service
	key      *secrets.MasterKey
	userID   string
	dataDir  string
	keyPath  string
	clockNow time.Time
}

func newSQLiteFixture(t *testing.T) *sqliteFixture {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	keyDir := filepath.Join(root, "keys")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cfg := config.Config{
		DataDir:              dataDir,
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          filepath.Join(dataDir, "registry.sqlite"),
		DatabaseMaxOpenConns: 8,
	}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test SQLite database: %v", err)
		}
	})
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	userID, err := insertActiveTestUser(ctx, db, "mfa.admin")
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(db, config.SQLite, &key)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &sqliteFixture{
		db:      db,
		service: service,
		key:     &key,
		userID:  userID,
		dataDir: dataDir,
		keyPath: keyPath,
		clockNow: time.Date(
			2026, time.October, 19, 12, 0, 0, 0, time.UTC,
		),
	}
	service.now = func() time.Time {
		return fixture.clockNow
	}
	return fixture
}

func insertActiveTestUser(ctx context.Context, db *sql.DB, loginName string) (string, error) {
	userID, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_users
		(user_id, display_name, email, email_verified, status, created_at, updated_at)
		VALUES (?, ?, ?, 0, 'active', ?, ?)`, userID.String(), "Synthetic MFA Admin", "mfa@example.invalid", now, now); err != nil {
		return "", err
	}
	passwordHash := "$argon2id$v=19$m=65536,t=3,p=1$c3ludGhldGljU2FsdA$" + strings.Repeat("A", 43)
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_local_credentials
		(user_id, login_name, password_hash, created_at, updated_at, password_changed_at)
		VALUES (?, ?, ?, ?, ?, ?)`, userID.String(), loginName, passwordHash, now, now, now); err != nil {
		return "", err
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO registry_instance_admins (user_id, granted_by, granted_at) VALUES (?, ?, ?)", userID.String(), userID.String(), now); err != nil {
		return "", err
	}
	return userID.String(), nil
}
