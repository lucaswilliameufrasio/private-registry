//go:build integration && linux

package mfa

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/secrets"
	"private-registry/internal/testinfra"
)

func TestPostgresEncryptedTOTPEnrollmentAndAtomicRecoveryConsumption(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
		DatabaseMaxOpenConns: 8,
	}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test PostgreSQL database: %v", err)
		}
	})
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	userID, err := insertPostgresTestUser(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

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
	service, err := New(db, config.Postgres, &key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time {
		return now
	}

	enrollment, err := service.BeginEnrollment(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := decodeTOTPSecret(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	var envelope []byte
	if err := db.QueryRowContext(ctx,
		"SELECT secret_envelope FROM registry_totp_credentials WHERE user_id = $1", userID).Scan(&envelope); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope, seed) || bytes.Contains(envelope, []byte(enrollment.Secret)) {
		t.Fatal("PostgreSQL persisted the TOTP seed in plaintext")
	}
	code := generateTOTPCode(seed, now.Unix()/totpPeriodSeconds)
	recoveryCodes, err := service.ConfirmEnrollment(ctx, userID, code)
	if err != nil {
		t.Fatal(err)
	}
	if len(recoveryCodes) != recoveryCodeCount {
		t.Fatalf("got %d recovery codes, want %d", len(recoveryCodes), recoveryCodeCount)
	}

	const callers = 6
	start := make(chan struct{})
	type result struct {
		consumed bool
		err      error
	}
	results := make(chan result, callers)
	var waitGroup sync.WaitGroup
	for range callers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			consumed, err := service.ConsumeRecoveryCode(ctx, userID, recoveryCodes[0])
			results <- result{consumed: consumed, err: err}
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)

	successes := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent PostgreSQL recovery consumption failed: %v", result.err)
		}
		if result.consumed {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("PostgreSQL recovery code was consumed %d times, want exactly once", successes)
	}
	var remaining int
	if err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM registry_mfa_recovery_codes WHERE user_id = $1 AND consumed_at IS NULL", userID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != recoveryCodeCount-1 {
		t.Fatalf("got %d unconsumed PostgreSQL recovery codes, want %d", remaining, recoveryCodeCount-1)
	}
}

func insertPostgresTestUser(ctx context.Context, db *sql.DB) (string, error) {
	userID, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_users
		(user_id, display_name, email, email_verified, status, created_at, updated_at)
		VALUES ($1, $2, $3, FALSE, 'active', $4, $5)`, userID.String(), "Synthetic MFA Admin", "mfa@example.invalid", now, now); err != nil {
		return "", err
	}
	passwordHash := "$argon2id$v=19$m=65536,t=3,p=1$c3ludGhldGljU2FsdA$" + strings.Repeat("A", 43)
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_local_credentials
		(user_id, login_name, password_hash, created_at, updated_at, password_changed_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, userID.String(), "mfa.postgres", passwordHash, now, now, now); err != nil {
		return "", err
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO registry_instance_admins (user_id, granted_by, granted_at) VALUES ($1, $2, $3)", userID.String(), userID.String(), now); err != nil {
		return "", err
	}
	return userID.String(), nil
}
