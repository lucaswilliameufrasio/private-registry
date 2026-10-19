//go:build linux

package auth

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/password"
	"private-registry/internal/secrets"
)

type sqliteFixture struct {
	db       *sql.DB
	service  *Service
	key      *secrets.MasterKey
	password []byte
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

	cfg := config.Config{
		DataDir:              dataDir,
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          filepath.Join(dataDir, "registry.sqlite"),
		DatabaseMaxOpenConns: 8,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
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
	service, err := New(db, config.SQLite, &key)
	if err != nil {
		t.Fatal(err)
	}
	return &sqliteFixture{
		db:       db,
		service:  service,
		key:      &key,
		password: []byte("synthetic-auth-password-never-reuse"),
	}
}

func (f *sqliteFixture) addAccount(t *testing.T, login, status string, instanceAdmin bool, workspaceRole string) string {
	t.Helper()
	ctx := context.Background()
	userID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	passwordHash, err := password.Hash(f.password)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := f.db.ExecContext(ctx, `INSERT INTO registry_users
		(user_id, display_name, email, email_verified, status, created_at, updated_at)
		VALUES (?, ?, ?, 0, ?, ?, ?)`, userID.String(), login, "auth@example.invalid", status, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(ctx, `INSERT INTO registry_local_credentials
		(user_id, login_name, password_hash, created_at, updated_at, password_changed_at)
		VALUES (?, ?, ?, ?, ?, ?)`, userID.String(), login, passwordHash, now, now, now); err != nil {
		t.Fatal(err)
	}
	if instanceAdmin {
		if _, err := f.db.ExecContext(ctx,
			"INSERT INTO registry_instance_admins (user_id, granted_by, granted_at) VALUES (?, ?, ?)", userID.String(), userID.String(), now); err != nil {
			t.Fatal(err)
		}
	}
	if workspaceRole != "" {
		workspaceID, err := uuid.NewV7()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.ExecContext(ctx, `INSERT INTO registry_workspaces
			(workspace_id, slug, display_name, status, created_by, created_at)
			VALUES (?, ?, ?, 'active', ?, ?)`, workspaceID.String(), "workspace-"+login, "Synthetic Workspace", userID.String(), now); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.ExecContext(ctx, `INSERT INTO registry_workspace_memberships
			(workspace_id, user_id, role, status, created_by, created_at, updated_at)
			VALUES (?, ?, ?, 'active', ?, ?, ?)`, workspaceID.String(), userID.String(), workspaceRole, userID.String(), now, now); err != nil {
			t.Fatal(err)
		}
	}
	return userID.String()
}
