package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/secrets"
)

const (
	enrollmentLifetime = 10 * time.Minute
	recoveryCodeCount  = 10
	recoveryCodeBytes  = 16
	totpIssuer         = "Private Registry"
)

var (
	ErrServiceUnavailable = errors.New("MFA service is unavailable")
	ErrInvalidUser        = errors.New("MFA user identity is invalid")
	ErrUserUnavailable    = errors.New("MFA user is unavailable")
	ErrMFAStorage         = errors.New("MFA state could not be read or written")
	ErrEncryption         = errors.New("MFA secret encryption is unavailable")
	ErrEnrollmentRequired = errors.New("MFA enrollment is not available")
	ErrEnrollmentExpired  = errors.New("MFA enrollment has expired")
	ErrFactorEnrolled     = errors.New("an active TOTP factor already exists")
	ErrInvalidCode        = errors.New("MFA code is invalid")
)

type Enrollment struct {
	// Secret and OTPAuthURL reveal the pending TOTP seed and must be handled as a secret.
	Secret     string
	OTPAuthURL string
	ExpiresAt  time.Time
}

type Service struct {
	db     *sql.DB
	driver config.DatabaseDriver
	key    *secrets.MasterKey
	now    func() time.Time
}

type recoveryCode struct {
	id        string
	plaintext string
	hash      string
}

type factorRecord struct {
	envelope    []byte
	status      string
	expiresAt   string
	confirmedAt sql.NullString
	lastTOTPAt  sql.NullInt64
}

func New(db *sql.DB, driver config.DatabaseDriver, key *secrets.MasterKey) (*Service, error) {
	if db == nil || key == nil {
		return nil, ErrServiceUnavailable
	}
	if driver != config.SQLite && driver != config.Postgres {
		return nil, ErrServiceUnavailable
	}
	return &Service{db: db, driver: driver, key: key, now: time.Now}, nil
}

// BeginEnrollment prepares a short-lived, encrypted TOTP seed for an active user.
// Callers must derive userID from a verified server-side principal; this method
// does not grant a session or establish authorization by itself.
func (s *Service) BeginEnrollment(ctx context.Context, userID string) (Enrollment, error) {
	now, err := s.currentTime()
	if err != nil {
		return Enrollment{}, err
	}
	var enrollment Enrollment
	err = s.withUserTransaction(ctx, userID, func(tx *sql.Tx, normalizedUserID string) error {
		accountName, err := readAccountName(ctx, tx, s.driver, normalizedUserID)
		if err != nil {
			return err
		}

		var existing factorRecord
		err = readFactor(ctx, tx, s.driver, normalizedUserID, &existing)
		if err == nil {
			if existing.status == "active" {
				return ErrFactorEnrolled
			}
			if existing.status != "pending" {
				return ErrMFAStorage
			}
			expiresAt, parseErr := time.Parse(time.RFC3339Nano, existing.expiresAt)
			if parseErr != nil {
				return ErrMFAStorage
			}
			if now.Before(expiresAt) {
				secret, openErr := s.openSecret(existing.envelope, normalizedUserID)
				if openErr != nil {
					return openErr
				}
				defer clear(secret)
				enrollment = newEnrollment(encodeTOTPSecret(secret), accountName, expiresAt)
				return nil
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}

		secret := make([]byte, totpSecretBytes)
		defer clear(secret)
		if _, err := rand.Read(secret); err != nil {
			return ErrMFAStorage
		}
		envelope, err := s.sealSecret(secret, normalizedUserID)
		if err != nil {
			return err
		}
		expiresAt := now.Add(enrollmentLifetime)
		nowText := now.Format(time.RFC3339Nano)
		query := `INSERT INTO registry_totp_credentials
			(user_id, secret_envelope, status, enrollment_expires_at, confirmed_at, last_accepted_step, created_at, updated_at)
			VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, 'pending', ` + bind(s.driver, 3) + `, NULL, NULL, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `)
			ON CONFLICT (user_id) DO UPDATE SET secret_envelope = excluded.secret_envelope,
				status = 'pending', enrollment_expires_at = excluded.enrollment_expires_at,
				confirmed_at = NULL, last_accepted_step = NULL,
				created_at = excluded.created_at, updated_at = excluded.updated_at`
		if _, err := tx.ExecContext(ctx, query,
			normalizedUserID, envelope, expiresAt.Format(time.RFC3339Nano), nowText, nowText); err != nil {
			return ErrMFAStorage
		}
		enrollment = newEnrollment(encodeTOTPSecret(secret), accountName, expiresAt)
		return nil
	})
	if err != nil {
		return Enrollment{}, err
	}
	return enrollment, nil
}

// ConfirmEnrollment activates the pending TOTP seed and returns recovery codes
// exactly once. No session is created by this operation.
func (s *Service) ConfirmEnrollment(ctx context.Context, userID, code string) ([]string, error) {
	if !validTOTPCode(code) {
		return nil, ErrInvalidCode
	}
	now, err := s.currentTime()
	if err != nil {
		return nil, err
	}
	var plaintextCodes []string
	err = s.withUserTransaction(ctx, userID, func(tx *sql.Tx, normalizedUserID string) error {
		var factor factorRecord
		if err := readFactor(ctx, tx, s.driver, normalizedUserID, &factor); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrEnrollmentRequired
			}
			return err
		}
		if factor.status == "active" {
			return ErrFactorEnrolled
		}
		if factor.status != "pending" {
			return ErrMFAStorage
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, factor.expiresAt)
		if err != nil {
			return ErrMFAStorage
		}
		if !now.Before(expiresAt) {
			return ErrEnrollmentExpired
		}
		secret, err := s.openSecret(factor.envelope, normalizedUserID)
		if err != nil {
			return err
		}
		defer clear(secret)
		acceptedStep, matched := matchingTOTPCode(secret, code, now.Unix())
		if !matched {
			return ErrInvalidCode
		}

		codes, err := generateRecoveryCodes()
		if err != nil {
			return ErrMFAStorage
		}
		confirmedAt := now.Format(time.RFC3339Nano)
		query := `UPDATE registry_totp_credentials SET status = 'active', confirmed_at = ` + bind(s.driver, 1) +
			`, last_accepted_step = ` + bind(s.driver, 2) + `, updated_at = ` + bind(s.driver, 3) +
			` WHERE user_id = ` + bind(s.driver, 4) + ` AND status = 'pending'`
		result, err := tx.ExecContext(ctx, query, confirmedAt, acceptedStep, confirmedAt, normalizedUserID)
		if err != nil {
			return ErrMFAStorage
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil || rowsAffected != 1 {
			return ErrMFAStorage
		}
		for _, recovery := range codes {
			insert := `INSERT INTO registry_mfa_recovery_codes (code_id, user_id, code_hash, issued_at, consumed_at)
				VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, NULL)`
			if _, err := tx.ExecContext(ctx, insert, recovery.id, normalizedUserID, recovery.hash, confirmedAt); err != nil {
				return ErrMFAStorage
			}
			plaintextCodes = append(plaintextCodes, recovery.plaintext)
		}
		if err := recordAudit(ctx, tx, s.driver, normalizedUserID, "mfa.totp.enrolled", confirmedAt); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return plaintextCodes, nil
}

// VerifyTOTP accepts a valid, non-replayed code for an active factor. Callers
// must already have verified the user's other required credential and must not
// grant a session until the complete authentication policy succeeds.
func (s *Service) VerifyTOTP(ctx context.Context, userID, code string) (bool, error) {
	if !validTOTPCode(code) {
		return false, nil
	}
	now, err := s.currentTime()
	if err != nil {
		return false, err
	}
	verified := false
	err = s.withUserTransaction(ctx, userID, func(tx *sql.Tx, normalizedUserID string) error {
		var factor factorRecord
		if err := readFactor(ctx, tx, s.driver, normalizedUserID, &factor); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		if factor.status != "active" {
			return nil
		}
		if !factor.confirmedAt.Valid || !factor.lastTOTPAt.Valid {
			return ErrMFAStorage
		}
		secret, err := s.openSecret(factor.envelope, normalizedUserID)
		if err != nil {
			return err
		}
		defer clear(secret)
		acceptedStep, matched := matchingTOTPCode(secret, code, now.Unix())
		if !matched || acceptedStep <= factor.lastTOTPAt.Int64 {
			return nil
		}
		query := `UPDATE registry_totp_credentials SET last_accepted_step = ` + bind(s.driver, 1) +
			`, updated_at = ` + bind(s.driver, 2) + ` WHERE user_id = ` + bind(s.driver, 3) +
			` AND status = 'active' AND last_accepted_step < ` + bind(s.driver, 4)
		result, err := tx.ExecContext(ctx, query, acceptedStep, now.Format(time.RFC3339Nano), normalizedUserID, acceptedStep)
		if err != nil {
			return ErrMFAStorage
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil || rowsAffected != 1 {
			return ErrMFAStorage
		}
		verified = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return verified, nil
}

// ConsumeRecoveryCode atomically consumes one active-factor recovery code.
// Callers must verify the user's other required credential and must not grant
// a session until the complete authentication policy succeeds.
func (s *Service) ConsumeRecoveryCode(ctx context.Context, userID, code string) (bool, error) {
	normalizedCode, ok := normalizeRecoveryCode(code)
	if !ok {
		return false, nil
	}
	now, err := s.currentTime()
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256([]byte(normalizedCode))
	codeHash := hex.EncodeToString(digest[:])
	consumed := false
	err = s.withUserTransaction(ctx, userID, func(tx *sql.Tx, normalizedUserID string) error {
		var status string
		query := "SELECT status FROM registry_totp_credentials WHERE user_id = " + bind(s.driver, 1)
		if err := tx.QueryRowContext(ctx, query, normalizedUserID).Scan(&status); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return ErrMFAStorage
		}
		if status != "active" {
			return nil
		}
		update := `UPDATE registry_mfa_recovery_codes SET consumed_at = ` + bind(s.driver, 1) +
			` WHERE user_id = ` + bind(s.driver, 2) + ` AND code_hash = ` + bind(s.driver, 3) + ` AND consumed_at IS NULL`
		result, err := tx.ExecContext(ctx, update, now.Format(time.RFC3339Nano), normalizedUserID, codeHash)
		if err != nil {
			return ErrMFAStorage
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return ErrMFAStorage
		}
		if rowsAffected == 0 {
			return nil
		}
		if rowsAffected != 1 {
			return ErrMFAStorage
		}
		if err := recordAudit(ctx, tx, s.driver, normalizedUserID, "mfa.recovery_code.used", now.Format(time.RFC3339Nano)); err != nil {
			return err
		}
		consumed = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return consumed, nil
}

func (s *Service) HasActiveFactor(ctx context.Context, userID string) (bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return false, ErrServiceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	normalizedUserID, err := normalizeUserID(userID)
	if err != nil {
		return false, err
	}
	query := `SELECT EXISTS (
		SELECT 1 FROM registry_totp_credentials AS factors
		JOIN registry_users AS users ON users.user_id = factors.user_id
		WHERE factors.user_id = ` + bind(s.driver, 1) + ` AND factors.status = 'active' AND users.status = 'active'
	)`
	var exists bool
	if err := s.db.QueryRowContext(ctx, query, normalizedUserID).Scan(&exists); err != nil {
		return false, ErrMFAStorage
	}
	return exists, nil
}

func (s *Service) currentTime() (time.Time, error) {
	if s == nil || s.db == nil || s.key == nil || s.now == nil {
		return time.Time{}, ErrServiceUnavailable
	}
	return s.now().UTC(), nil
}

func (s *Service) withUserTransaction(
	ctx context.Context,
	userID string,
	operation func(*sql.Tx, string) error,
) (retErr error) {
	if s == nil || s.db == nil || operation == nil || ctx == nil {
		return ErrServiceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	normalizedUserID, err := normalizeUserID(userID)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrMFAStorage
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			retErr = errors.Join(retErr, ErrMFAStorage)
		}
	}()
	if err := lockActiveUser(ctx, tx, s.driver, normalizedUserID); err != nil {
		return err
	}
	if err := operation(tx, normalizedUserID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrMFAStorage
	}
	return nil
}

func lockActiveUser(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, userID string) error {
	if driver == config.Postgres {
		query := "SELECT user_id FROM registry_users WHERE user_id = $1 AND status = 'active' FOR UPDATE"
		var lockedUserID string
		if err := tx.QueryRowContext(ctx, query, userID).Scan(&lockedUserID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrUserUnavailable
			}
			return ErrMFAStorage
		}
		return nil
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE registry_users SET updated_at = updated_at WHERE user_id = ? AND status = 'active'", userID)
	if err != nil {
		return ErrMFAStorage
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return ErrMFAStorage
	}
	if rowsAffected != 1 {
		return ErrUserUnavailable
	}
	return nil
}

func readAccountName(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, userID string) (string, error) {
	query := `SELECT COALESCE(credentials.login_name, users.display_name)
		FROM registry_users AS users
		LEFT JOIN registry_local_credentials AS credentials ON credentials.user_id = users.user_id
		WHERE users.user_id = ` + bind(driver, 1) + ` AND users.status = 'active'`
	var accountName string
	if err := tx.QueryRowContext(ctx, query, userID).Scan(&accountName); err != nil {
		return "", ErrMFAStorage
	}
	if strings.TrimSpace(accountName) == "" {
		return "", ErrMFAStorage
	}
	return accountName, nil
}

func readFactor(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, userID string, factor *factorRecord) error {
	if factor == nil {
		return ErrMFAStorage
	}
	query := `SELECT secret_envelope, status, enrollment_expires_at, confirmed_at, last_accepted_step
		FROM registry_totp_credentials WHERE user_id = ` + bind(driver, 1)
	err := tx.QueryRowContext(ctx, query, userID).Scan(
		&factor.envelope, &factor.status, &factor.expiresAt, &factor.confirmedAt, &factor.lastTOTPAt)
	return err
}

func (s *Service) sealSecret(secret []byte, userID string) ([]byte, error) {
	envelope, err := s.key.Seal(secret, encryptionContext(userID))
	if err != nil {
		return nil, ErrEncryption
	}
	return envelope, nil
}

func (s *Service) openSecret(envelope []byte, userID string) ([]byte, error) {
	secret, err := s.key.Open(envelope, encryptionContext(userID))
	if err != nil {
		return nil, ErrEncryption
	}
	if len(secret) != totpSecretBytes {
		clear(secret)
		return nil, ErrMFAStorage
	}
	return secret, nil
}

func encryptionContext(userID string) []byte {
	return []byte("mfa-credential/" + userID + "/totp-seed/v1")
}

func newEnrollment(secret, accountName string, expiresAt time.Time) Enrollment {
	label := url.PathEscape(totpIssuer) + ":" + url.PathEscape(accountName)
	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", totpIssuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", fmt.Sprintf("%d", totpDigits))
	query.Set("period", fmt.Sprintf("%d", totpPeriodSeconds))
	return Enrollment{
		Secret:     secret,
		OTPAuthURL: "otpauth://totp/" + label + "?" + query.Encode(),
		ExpiresAt:  expiresAt,
	}
}

func generateRecoveryCodes() ([]recoveryCode, error) {
	recoveryCodes := make([]recoveryCode, 0, recoveryCodeCount)
	for range recoveryCodeCount {
		var randomCode [recoveryCodeBytes]byte
		if _, err := rand.Read(randomCode[:]); err != nil {
			clear(randomCode[:])
			return nil, err
		}
		compact := hex.EncodeToString(randomCode[:])
		clear(randomCode[:])
		formatted := compact[:8] + "-" + compact[8:16] + "-" + compact[16:24] + "-" + compact[24:]
		digest := sha256.Sum256([]byte(compact))
		codeID, err := uuid.NewV7()
		if err != nil {
			return nil, err
		}
		recoveryCodes = append(recoveryCodes, recoveryCode{
			id:        codeID.String(),
			plaintext: formatted,
			hash:      hex.EncodeToString(digest[:]),
		})
	}
	return recoveryCodes, nil
}

func normalizeRecoveryCode(code string) (string, bool) {
	compact := strings.ToLower(strings.TrimSpace(code))
	compact = strings.ReplaceAll(compact, "-", "")
	compact = strings.ReplaceAll(compact, " ", "")
	if len(compact) != recoveryCodeBytes*2 {
		return "", false
	}
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != recoveryCodeBytes {
		return "", false
	}
	clear(decoded)
	return compact, true
}

func recordAudit(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, actorID, action, occurredAt string) error {
	eventID, err := uuid.NewV7()
	if err != nil {
		return ErrMFAStorage
	}
	query := `INSERT INTO registry_audit_events
		(event_id, actor_user_id, actor_type, actor_label, action, target_type, target_id, outcome, occurred_at)
		VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, 'user', NULL, ` + bind(driver, 3) +
		`, 'user', ` + bind(driver, 4) + `, 'succeeded', ` + bind(driver, 5) + `)`
	if _, err := tx.ExecContext(ctx, query, eventID.String(), actorID, action, actorID, occurredAt); err != nil {
		return ErrMFAStorage
	}
	return nil
}

func normalizeUserID(userID string) (string, error) {
	parsed, err := uuid.Parse(userID)
	if err != nil || parsed == uuid.Nil {
		return "", ErrInvalidUser
	}
	return parsed.String(), nil
}

func bind(driver config.DatabaseDriver, position int) string {
	if driver == config.Postgres {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}
