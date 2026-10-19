package sessions

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
)

type sqliteFixture struct {
	db     *sql.DB
	store  *Store
	userID string
	now    time.Time
}

func newSQLiteFixture(t *testing.T) *sqliteFixture {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "registry-data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
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
	userID, err := insertTestUser(ctx, db, config.SQLite, "session.test")
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &sqliteFixture{
		db:     db,
		store:  store,
		userID: userID,
		now:    time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC),
	}
	store.now = func() time.Time {
		return fixture.now
	}
	return fixture
}

func insertTestUser(ctx context.Context, db *sql.DB, driver config.DatabaseDriver, loginName string) (string, error) {
	userID, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	insert := `INSERT INTO registry_users
		(user_id, display_name, email, email_verified, status, created_at, updated_at)
		VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, ` + bind(driver, 3) + `, ` + boolValue(driver) +
		`, 'active', ` + bind(driver, 4) + `, ` + bind(driver, 5) + `)`
	if _, err := db.ExecContext(ctx, insert, userID.String(), loginName, "session@example.invalid", now, now); err != nil {
		return "", err
	}
	return userID.String(), nil
}

func insertActiveFactor(ctx context.Context, db *sql.DB, driver config.DatabaseDriver, userID string) error {
	now := time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	query := `INSERT INTO registry_totp_credentials
		(user_id, secret_envelope, status, enrollment_expires_at, confirmed_at,
		 last_accepted_step, created_at, updated_at)
		VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, 'active', ` + bind(driver, 3) +
		`, ` + bind(driver, 4) + `, 1, ` + bind(driver, 5) + `, ` + bind(driver, 6) + `)`
	_, err := db.ExecContext(ctx, query, userID, make([]byte, 61), now, now, now, now)
	return err
}

func boolValue(driver config.DatabaseDriver) string {
	if driver == config.Postgres {
		return "FALSE"
	}
	return "0"
}
