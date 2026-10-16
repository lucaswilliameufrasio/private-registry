package bootstrap

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
)

func TestCreateFirstAdminPersistsCredentialAndAuditsOperator(t *testing.T) {
	db, cfg := openSQLite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	if err := CheckReady(ctx, db, config.SQLite); err != nil {
		t.Fatalf("fresh migrated installation is not ready: %v", err)
	}

	password := []byte("correct horse battery staple 42")
	defer clear(password)
	input := validAdminInput(password)
	userID, err := CreateFirstAdmin(ctx, db, config.SQLite, input)
	if err != nil {
		t.Fatal(err)
	}
	parsedUserID, err := uuid.Parse(userID)
	if err != nil || parsedUserID.Version() != 7 {
		t.Fatalf("administrator ID is not UUIDv7: %q (%v)", userID, err)
	}

	var displayName, email, status string
	var emailVerified bool
	if err := db.QueryRowContext(ctx,
		"SELECT display_name, email, status, email_verified FROM registry_users WHERE user_id = ?", userID).
		Scan(&displayName, &email, &status, &emailVerified); err != nil {
		t.Fatal(err)
	}
	if displayName != "Registry Operator" || email != "admin@example.test" || status != "active" || emailVerified {
		t.Fatalf("unexpected bootstrap account: name=%q email=%q status=%q verified=%t", displayName, email, status, emailVerified)
	}

	var loginName, encodedHash string
	if err := db.QueryRowContext(ctx,
		"SELECT login_name, password_hash FROM registry_local_credentials WHERE user_id = ?", userID).
		Scan(&loginName, &encodedHash); err != nil {
		t.Fatal(err)
	}
	if loginName != "first.admin" {
		t.Fatalf("unexpected normalized login name: %q", loginName)
	}
	verifyEncodedPassword(t, encodedHash, password)

	var grantedBy sql.NullString
	if err := db.QueryRowContext(ctx,
		"SELECT granted_by FROM registry_instance_admins WHERE user_id = ?", userID).Scan(&grantedBy); err != nil {
		t.Fatal(err)
	}
	if grantedBy.Valid {
		t.Fatalf("bootstrap administrator has unexpected granting user %q", grantedBy.String)
	}

	var actorType, actorLabel, action, targetID, outcome string
	if err := db.QueryRowContext(ctx, `SELECT actor_type, actor_label, action, target_id, outcome
		FROM registry_audit_events WHERE target_type = 'user' AND target_id = ?`, userID).
		Scan(&actorType, &actorLabel, &action, &targetID, &outcome); err != nil {
		t.Fatal(err)
	}
	if actorType != "operator" || actorLabel != "registry-host-user" || action != "instance_admin.bootstrap" || targetID != userID || outcome != "succeeded" {
		t.Fatalf("unexpected bootstrap audit record: actor=%q label=%q action=%q target=%q outcome=%q",
			actorType, actorLabel, action, targetID, outcome)
	}

	if err := CheckReady(ctx, db, config.SQLite); !errors.Is(err, ErrAlreadyBootstrapped) {
		t.Fatalf("second readiness check did not refuse a completed bootstrap: %v", err)
	}
	if _, err := CreateFirstAdmin(ctx, db, config.SQLite, input); !errors.Is(err, ErrAlreadyBootstrapped) {
		t.Fatalf("second bootstrap unexpectedly succeeded: %v", err)
	}
}

func TestCreateFirstAdminRollsBackAllRecordsWhenAuditFails(t *testing.T) {
	db, cfg := openSQLite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER reject_bootstrap_audit
		BEFORE INSERT ON registry_audit_events
		WHEN NEW.action = 'instance_admin.bootstrap'
		BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END`); err != nil {
		t.Fatal(err)
	}

	password := []byte("another sufficiently long password")
	defer clear(password)
	if _, err := CreateFirstAdmin(ctx, db, config.SQLite, validAdminInput(password)); !errors.Is(err, ErrPersistence) {
		t.Fatalf("expected sanitized persistence error after the audit fault, got %v", err)
	}

	for _, table := range []string{"registry_users", "registry_local_credentials", "registry_instance_admins", "registry_audit_events"} {
		var count int
		query := "SELECT count(*) FROM " + table
		if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("failed bootstrap left %d records in %s", count, table)
		}
	}
}

func TestCreateFirstAdminSerializesConcurrentSQLiteBootstrap(t *testing.T) {
	db, cfg := openSQLite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}

	inputs := []AdminInput{
		validAdminInput([]byte("first valid password for the race")),
		{
			LoginName:     "second.admin",
			DisplayName:   "Second Operator",
			Email:         "second.admin@example.test",
			Password:      []byte("second valid password for the race"),
			OperatorLabel: "another-host-user",
		},
	}
	start := make(chan struct{})
	type result struct {
		userID string
		err    error
	}
	results := make(chan result, len(inputs))
	var waitGroup sync.WaitGroup
	for _, input := range inputs {
		waitGroup.Add(1)
		go func(input AdminInput) {
			defer waitGroup.Done()
			<-start
			userID, err := CreateFirstAdmin(ctx, db, config.SQLite, input)
			clear(input.Password)
			results <- result{userID: userID, err: err}
		}(input)
	}
	close(start)
	waitGroup.Wait()
	close(results)

	successes := 0
	alreadyBootstrapped := 0
	for result := range results {
		if result.err == nil {
			successes++
			if result.userID == "" {
				t.Error("successful SQLite bootstrap returned an empty user identity")
			}
			continue
		}
		if errors.Is(result.err, ErrAlreadyBootstrapped) {
			alreadyBootstrapped++
			continue
		}
		t.Errorf("unexpected concurrent SQLite bootstrap result: %v", result.err)
	}
	if successes != 1 || alreadyBootstrapped != 1 {
		t.Fatalf("bootstrap did not serialize to one winner: successes=%d already=%d", successes, alreadyBootstrapped)
	}

	for _, table := range []string{"registry_users", "registry_local_credentials", "registry_instance_admins", "registry_audit_events"} {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("concurrent bootstrap left %d records in %s, want exactly one", count, table)
		}
	}
}

func TestCreateFirstAdminRequiresExplicitMigrations(t *testing.T) {
	db, _ := openSQLite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	password := []byte("correct horse battery staple 42")
	defer clear(password)
	if err := CheckReady(ctx, db, config.SQLite); !errors.Is(err, ErrMigrationsRequired) {
		t.Fatalf("unmigrated database was reported ready: %v", err)
	}
	if _, err := CreateFirstAdmin(ctx, db, config.SQLite, validAdminInput(password)); !errors.Is(err, ErrMigrationsRequired) {
		t.Fatalf("bootstrap implicitly migrated an unmigrated database: %v", err)
	}
}

func TestValidateAdminInputNormalizesLoginAndRejectsInvalidValues(t *testing.T) {
	password := []byte("password with enough length")
	input := validAdminInput(password)
	input.LoginName = "  FIRST.Admin  "
	validated, err := validateAdminInput(input)
	if err != nil {
		t.Fatal(err)
	}
	if validated.LoginName != "first.admin" || string(validated.Password) != string(password) {
		t.Fatalf("unexpected normalized input: login=%q password changed=%t", validated.LoginName, string(validated.Password) != string(password))
	}

	invalidInputs := []AdminInput{
		{LoginName: "ab", DisplayName: "Name", Email: "admin@example.test", Password: password, OperatorLabel: "operator"},
		{LoginName: "Kelvin", DisplayName: "Name", Email: "admin@example.test", Password: password, OperatorLabel: "operator"},
		{LoginName: "first.admin", DisplayName: "Name", Email: "not an email", Password: password, OperatorLabel: "operator"},
		{LoginName: "first.admin", DisplayName: "Name", Email: "admin@example.test", Password: []byte("short"), OperatorLabel: "operator"},
	}
	for index, invalid := range invalidInputs {
		if _, err := validateAdminInput(invalid); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("invalid input %d was accepted: %v", index, err)
		}
	}
}

func openSQLite(t *testing.T) (*sql.DB, config.Config) {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "registry-data")
	cfg := config.Config{
		DataDir:              dataDir,
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          filepath.Join(dataDir, "registry.sqlite"),
		DatabaseMaxOpenConns: 4,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close SQLite database: %v", err)
		}
	})
	return db, cfg
}

func validAdminInput(password []byte) AdminInput {
	return AdminInput{
		LoginName:     " First.Admin ",
		DisplayName:   " Registry Operator ",
		Email:         " admin@example.test ",
		Password:      password,
		OperatorLabel: " registry-host-user ",
	}
}

func verifyEncodedPassword(t *testing.T, encoded string, password []byte) {
	t.Helper()
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		t.Fatalf("password hash does not use the versioned Argon2id PHC format: %q", encoded)
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 {
		t.Fatalf("unexpected Argon2id parameters: %q", parts[3])
	}
	memoryText, ok := strings.CutPrefix(parameters[0], "m=")
	if !ok {
		t.Fatalf("missing Argon2id memory parameter: %q", parts[3])
	}
	memory, err := strconv.ParseUint(memoryText, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	iterationsText, ok := strings.CutPrefix(parameters[1], "t=")
	if !ok {
		t.Fatalf("missing Argon2id iteration parameter: %q", parts[3])
	}
	iterations, err := strconv.ParseUint(iterationsText, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	parallelismText, ok := strings.CutPrefix(parameters[2], "p=")
	if !ok {
		t.Fatalf("missing Argon2id parallelism parameter: %q", parts[3])
	}
	parallelism, err := strconv.ParseUint(parallelismText, 10, 8)
	if err != nil {
		t.Fatal(err)
	}
	if memory != uint64(argon2Memory) || iterations != uint64(argon2Iterations) || parallelism != uint64(argon2Parallelism) {
		t.Fatalf("unexpected Argon2id work factors: %q", parts[3])
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatal(err)
	}
	expectedKey, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatal(err)
	}
	actualKey := argon2.IDKey(password, salt, uint32(iterations), uint32(memory), uint8(parallelism), uint32(len(expectedKey)))
	defer clear(actualKey)
	if subtle.ConstantTimeCompare(actualKey, expectedKey) != 1 {
		t.Fatal("stored Argon2id hash does not match the submitted password")
	}
}
