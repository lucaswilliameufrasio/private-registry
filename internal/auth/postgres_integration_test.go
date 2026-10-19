//go:build integration && linux

package auth

import (
	"context"
	"database/sql"
	"encoding/base32"
	"errors"
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
	"private-registry/internal/sessions"
	"private-registry/internal/testinfra"
)

func TestPostgresAuthenticationEnforcesEnrollmentRecoveryAndAttemptLimits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	postgres, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := postgres.Stop(); err != nil {
			t.Errorf("stop owned PostgreSQL fixture: %v", err)
		}
	})
	cfg := config.Config{
		DatabaseDriver:       config.Postgres,
		DatabaseDSN:          postgres.DSN(),
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
	userID, loginPassword := insertPostgresAdmin(t, ctx, db)

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

	const sourceAddress = "192.0.2.90:443"
	enrollmentLogin, err := service.Login(ctx, "mfa.postgres", loginPassword, sourceAddress)
	if err != nil {
		t.Fatal(err)
	}
	if enrollmentLogin.Stage != StageMFAEnrollment || enrollmentLogin.Credentials.Session.UserID != userID {
		t.Fatalf("PostgreSQL admin did not receive a restricted enrollment stage: %+v", enrollmentLogin)
	}
	enrollment, err := service.BeginMFAEnrollment(ctx, enrollmentLogin.Credentials.BearerToken)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	code := generateTOTPCode(secret, time.Now().Unix()/30)
	completedEnrollment, err := service.CompleteMFAEnrollment(
		ctx, enrollmentLogin.Credentials.BearerToken, code, sourceAddress)
	if err != nil {
		t.Fatal(err)
	}
	if len(completedEnrollment.RecoveryCodes) != 10 || completedEnrollment.Credentials.Session.Level != sessions.LevelMFA {
		t.Fatalf("PostgreSQL enrollment did not activate TOTP and issue recovery codes: %+v", completedEnrollment)
	}

	challenge, err := service.Login(ctx, "mfa.postgres", loginPassword, sourceAddress)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Stage != StageMFAChallenge {
		t.Fatalf("PostgreSQL login bypassed enrolled MFA: %+v", challenge)
	}
	fullSession, err := service.CompleteMFA(ctx, challenge.Credentials.BearerToken, completedEnrollment.RecoveryCodes[0], sourceAddress)
	if err != nil {
		t.Fatal(err)
	}
	if fullSession.Session.Level != sessions.LevelMFA {
		t.Fatalf("recovery code did not complete PostgreSQL MFA: %+v", fullSession.Session)
	}

	secondChallenge, err := service.Login(ctx, "mfa.postgres", loginPassword, sourceAddress)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CompleteMFA(ctx, secondChallenge.Credentials.BearerToken, completedEnrollment.RecoveryCodes[0], sourceAddress); !errors.Is(err, ErrRejected) {
		t.Fatalf("PostgreSQL accepted a consumed recovery code: %v", err)
	}

	for range 5 {
		_, err := service.Login(ctx, "mfa.postgres", []byte("synthetic-invalid-password"), "192.0.2.91")
		if !errors.Is(err, ErrRejected) {
			t.Fatalf("bad password did not receive the generic error: %v", err)
		}
	}
	if _, err := service.Login(ctx, "mfa.postgres", loginPassword, "192.0.2.91"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("PostgreSQL did not persist the account attempt limit: %v", err)
	}
	var persistedBuckets int
	if err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM registry_auth_attempt_buckets WHERE octet_length(attempt_times) >= 8").Scan(&persistedBuckets); err != nil {
		t.Fatal(err)
	}
	if persistedBuckets == 0 {
		t.Fatal("PostgreSQL did not persist authentication attempt buckets")
	}
}

func insertPostgresAdmin(t *testing.T, ctx context.Context, db *sql.DB) (string, []byte) {
	t.Helper()
	userID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	loginPassword := []byte("synthetic-postgres-auth-password")
	passwordHash, err := password.Hash(loginPassword)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_users
		(user_id, display_name, email, email_verified, status, created_at, updated_at)
		VALUES ($1, $2, $3, FALSE, 'active', $4, $5)`, userID.String(), "Synthetic PostgreSQL Admin", "auth@example.invalid", now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_local_credentials
		(user_id, login_name, password_hash, created_at, updated_at, password_changed_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, userID.String(), "mfa.postgres", passwordHash, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO registry_instance_admins (user_id, granted_by, granted_at) VALUES ($1, $1, $2)", userID.String(), now); err != nil {
		t.Fatal(err)
	}
	return userID.String(), loginPassword
}
