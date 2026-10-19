package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/loginname"
	"private-registry/internal/password"
)

const (
	argon2Memory      uint32 = password.MemoryKiB
	argon2Iterations  uint32 = password.Iterations
	argon2Parallelism uint8  = password.Parallelism
	argon2SaltBytes          = password.SaltBytes
	argon2KeyBytes           = password.DerivedKeyBytes
)

var (
	ErrMigrationsRequired  = errors.New("database migrations are required; run registry migrate")
	ErrAlreadyBootstrapped = errors.New("installation already has an administrator")
	ErrInvalidInput        = errors.New("administrator details are invalid")
	ErrLoginNameTaken      = errors.New("local login name is already in use")
	ErrPersistence         = errors.New("first administrator could not be created")
)

type AdminInput struct {
	LoginName     string
	DisplayName   string
	Email         string
	Password      []byte
	OperatorLabel string
}

func CheckReady(ctx context.Context, db *sql.DB, driver config.DatabaseDriver) error {
	if ctx == nil || db == nil {
		return ErrPersistence
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if driver != config.SQLite && driver != config.Postgres {
		return ErrPersistence
	}

	requiredTables := []string{
		"registry_installation",
		"registry_users",
		"registry_local_credentials",
		"registry_instance_admins",
		"registry_audit_events",
		"goose_db_version",
	}
	for _, table := range requiredTables {
		exists, err := databaseTableExists(ctx, db, driver, table)
		if err != nil {
			return ErrPersistence
		}
		if !exists {
			return ErrMigrationsRequired
		}
	}

	var installationID string
	if err := db.QueryRowContext(ctx,
		"SELECT installation_id FROM registry_installation WHERE singleton_id = 1").Scan(&installationID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrMigrationsRequired
		}
		return ErrPersistence
	}
	parsedInstallationID, err := uuid.Parse(installationID)
	if err != nil || parsedInstallationID.Version() != 7 {
		return ErrMigrationsRequired
	}
	var migrationApplied bool
	if err := db.QueryRowContext(ctx,
		"SELECT COALESCE((SELECT is_applied FROM goose_db_version WHERE version_id = 3 ORDER BY id DESC LIMIT 1), FALSE)").Scan(&migrationApplied); err != nil {
		return ErrPersistence
	}
	if !migrationApplied {
		return ErrMigrationsRequired
	}

	var adminCount int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM registry_instance_admins").Scan(&adminCount); err != nil {
		return ErrPersistence
	}
	if adminCount > 0 {
		return ErrAlreadyBootstrapped
	}
	return nil
}

func CreateFirstAdmin(
	ctx context.Context,
	db *sql.DB,
	driver config.DatabaseDriver,
	input AdminInput,
) (string, error) {
	if ctx == nil || db == nil {
		return "", ErrPersistence
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if driver != config.SQLite && driver != config.Postgres {
		return "", ErrPersistence
	}

	validated, err := validateAdminInput(input)
	if err != nil {
		return "", err
	}
	if err := CheckReady(ctx, db, driver); err != nil {
		return "", err
	}
	passwordHash, err := hashPassword(validated.Password)
	if err != nil {
		return "", ErrPersistence
	}
	userID, err := uuid.NewV7()
	if err != nil {
		return "", ErrPersistence
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return "", ErrPersistence
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", ErrPersistence
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := lockInstallation(ctx, tx, driver); err != nil {
		return "", ErrPersistence
	}
	var adminCount int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM registry_instance_admins").Scan(&adminCount); err != nil {
		return "", ErrPersistence
	}
	if adminCount > 0 {
		return "", ErrAlreadyBootstrapped
	}

	var loginNameExists bool
	query := "SELECT EXISTS (SELECT 1 FROM registry_local_credentials WHERE login_name = " + bind(driver, 1) + ")"
	if err := tx.QueryRowContext(ctx, query, validated.LoginName).Scan(&loginNameExists); err != nil {
		return "", ErrPersistence
	}
	if loginNameExists {
		return "", ErrLoginNameTaken
	}

	insertUser := `INSERT INTO registry_users
		(user_id, display_name, email, created_at, updated_at)
		VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, ` + bind(driver, 3) + `, ` + bind(driver, 4) + `, ` + bind(driver, 5) + `)`
	if _, err := tx.ExecContext(ctx, insertUser,
		userID.String(), validated.DisplayName, validated.Email, now, now); err != nil {
		return "", ErrPersistence
	}

	insertCredential := `INSERT INTO registry_local_credentials
		(user_id, login_name, password_hash, created_at, updated_at, password_changed_at)
		VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, ` + bind(driver, 3) + `, ` + bind(driver, 4) + `, ` + bind(driver, 5) + `, ` + bind(driver, 6) + `)`
	if _, err := tx.ExecContext(ctx, insertCredential,
		userID.String(), validated.LoginName, passwordHash, now, now, now); err != nil {
		return "", ErrPersistence
	}

	insertAdmin := `INSERT INTO registry_instance_admins (user_id, granted_by, granted_at)
		VALUES (` + bind(driver, 1) + `, NULL, ` + bind(driver, 2) + `)`
	if _, err := tx.ExecContext(ctx, insertAdmin, userID.String(), now); err != nil {
		return "", ErrPersistence
	}

	insertAudit := `INSERT INTO registry_audit_events
		(event_id, actor_user_id, actor_type, actor_label, action, target_type, target_id, outcome, occurred_at)
		VALUES (` + bind(driver, 1) + `, NULL, 'operator', ` + bind(driver, 2) + `, 'instance_admin.bootstrap', 'user', ` + bind(driver, 3) + `, 'succeeded', ` + bind(driver, 4) + `)`
	if _, err := tx.ExecContext(ctx, insertAudit,
		eventID.String(), validated.OperatorLabel, userID.String(), now); err != nil {
		return "", ErrPersistence
	}

	if err := tx.Commit(); err != nil {
		return "", ErrPersistence
	}
	return userID.String(), nil
}

func validateAdminInput(input AdminInput) (AdminInput, error) {
	input.LoginName = normalizeLoginName(input.LoginName)
	if !validLoginName(input.LoginName) {
		return AdminInput{}, ErrInvalidInput
	}

	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if !validText(input.DisplayName, 1, 200) {
		return AdminInput{}, ErrInvalidInput
	}

	input.Email = strings.TrimSpace(input.Email)
	if !validEmail(input.Email) {
		return AdminInput{}, ErrInvalidInput
	}

	input.OperatorLabel = strings.TrimSpace(input.OperatorLabel)
	if !validText(input.OperatorLabel, 1, 200) {
		return AdminInput{}, ErrInvalidInput
	}

	if !utf8.Valid(input.Password) {
		return AdminInput{}, ErrInvalidInput
	}
	passwordRunes := utf8.RuneCount(input.Password)
	if passwordRunes < 15 || passwordRunes > 1024 {
		return AdminInput{}, ErrInvalidInput
	}
	remainingPassword := input.Password
	for len(remainingPassword) > 0 {
		character, size := utf8.DecodeRune(remainingPassword)
		if unicode.IsControl(character) {
			return AdminInput{}, ErrInvalidInput
		}
		remainingPassword = remainingPassword[size:]
	}
	return input, nil
}

func normalizeLoginName(loginName string) string {
	return loginname.Normalize(loginName)
}

func validLoginName(loginName string) bool {
	return loginname.Valid(loginName)
}

func validText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	runeCount := utf8.RuneCountInString(value)
	if runeCount < minimum || runeCount > maximum {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validEmail(value string) bool {
	if len(value) == 0 || len(value) > 254 || !validText(value, 3, 254) {
		return false
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value
}

func hashPassword(value []byte) (string, error) {
	return password.Hash(value)
}

func lockInstallation(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver) (string, error) {
	if driver == config.Postgres {
		var installationID string
		err := tx.QueryRowContext(ctx,
			"SELECT installation_id FROM registry_installation WHERE singleton_id = 1 FOR UPDATE").Scan(&installationID)
		return installationID, err
	}

	result, err := tx.ExecContext(ctx,
		"UPDATE registry_installation SET created_at = created_at WHERE singleton_id = 1")
	if err != nil {
		return "", err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected != 1 {
		return "", errors.New("installation singleton row is missing")
	}
	var installationID string
	err = tx.QueryRowContext(ctx,
		"SELECT installation_id FROM registry_installation WHERE singleton_id = 1").Scan(&installationID)
	return installationID, err
}

func databaseTableExists(ctx context.Context, db *sql.DB, driver config.DatabaseDriver, table string) (bool, error) {
	if driver == config.SQLite {
		var exists bool
		err := db.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)", table).Scan(&exists)
		return exists, err
	}
	var exists bool
	err := db.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists)
	return exists, err
}

func bind(driver config.DatabaseDriver, position int) string {
	if driver == config.Postgres {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}
