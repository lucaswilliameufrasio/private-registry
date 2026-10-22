package sessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
)

const (
	absoluteLifetime          = 12 * time.Hour
	idleLifetime              = time.Hour
	enrollmentSessionLifetime = 10 * time.Minute
	mfaChallengeLifetime      = 5 * time.Minute
	tokenBytes                = 32
)

type Level string

const (
	LevelEnrollmentOnly Level = "enrollment_only"
	LevelMFAChallenge   Level = "mfa_challenge"
	LevelStandard       Level = "standard"
	LevelMFA            Level = "mfa"
)

var (
	ErrServiceUnavailable = errors.New("session service is unavailable")
	ErrInvalidUser        = errors.New("session user identity is invalid")
	ErrInvalidLevel       = errors.New("session level is invalid")
	ErrSessionUnavailable = errors.New("session is unavailable")
	ErrUserUnavailable    = errors.New("session user is unavailable")
	ErrCSRF               = errors.New("CSRF token is invalid")
	ErrInvalidTransition  = errors.New("session authentication transition is invalid")
	ErrSessionStorage     = errors.New("session state could not be read or written")
)

type Session struct {
	ID                 string
	UserID             string
	Level              Level
	CreatedAt          time.Time
	LastActivityAt     time.Time
	AbsoluteExpiresAt  time.Time
	IdleExpiresAt      time.Time
	MFAAuthenticatedAt *time.Time
}

// Credentials are returned once when a session is issued or rotated. BearerToken
// and CSRFToken must not be logged or persisted by callers.
type Credentials struct {
	BearerToken string
	CSRFToken   string
	Session     Session
}

type Store struct {
	db     *sql.DB
	driver config.DatabaseDriver
	now    func() time.Time
}

type sessionRecord struct {
	Session
	bearerHash string
	csrfHash   string
	revokedAt  sql.NullString
}

func New(db *sql.DB, driver config.DatabaseDriver) (*Store, error) {
	if db == nil || (driver != config.SQLite && driver != config.Postgres) {
		return nil, ErrServiceUnavailable
	}
	return &Store{db: db, driver: driver, now: time.Now}, nil
}

// Create persists only hashes of the opaque bearer and CSRF tokens. The caller
// must select the level only after completing the corresponding authentication
// policy; LevelEnrollmentOnly must be restricted to factor setup.
func (s *Store) Create(ctx context.Context, userID string, level Level) (credentials Credentials, retErr error) {
	if err := s.validate(); err != nil {
		return Credentials{}, err
	}
	if !validLevel(level) {
		return Credentials{}, ErrInvalidLevel
	}
	if level == LevelMFA {
		return Credentials{}, ErrInvalidTransition
	}
	if ctx == nil {
		return Credentials{}, ErrServiceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Credentials{}, err
	}
	normalizedUserID, err := normalizeUserID(userID)
	if err != nil {
		return Credentials{}, err
	}
	now := s.now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Credentials{}, ErrSessionStorage
	}
	defer rollbackTransaction(tx, &retErr)
	if err := lockActiveUser(ctx, tx, s.driver, normalizedUserID); err != nil {
		return Credentials{}, err
	}
	credentials, err = s.createInTransaction(ctx, tx, normalizedUserID, level, now)
	if err != nil {
		return Credentials{}, err
	}
	if err := recordAudit(ctx, tx, s.driver, normalizedUserID, "session.created", "session", credentials.Session.ID, now); err != nil {
		return Credentials{}, err
	}
	if err := tx.Commit(); err != nil {
		return Credentials{}, ErrSessionStorage
	}
	return credentials, nil
}

// Validate checks that the bearer is active, the account is active, and the
// session is within both expiry limits. Successful requests extend only the
// inactivity deadline, never the absolute deadline.
func (s *Store) Validate(ctx context.Context, bearerToken string) (Session, error) {
	return s.validateBearer(ctx, bearerToken, "", false)
}

// ValidateWithCSRF performs session validation and CSRF-token validation in the
// same transaction. HTTP middleware must also validate Origin against the
// configured canonical origin before allowing a browser write.
func (s *Store) ValidateWithCSRF(ctx context.Context, bearerToken, csrfToken string) (Session, error) {
	return s.validateBearer(ctx, bearerToken, csrfToken, true)
}

// Rotate revokes the current bearer and creates a fresh session atomically.
// Callers must validate CSRF and complete the required reauthentication/MFA
// checks before requesting a rotation.
func (s *Store) Rotate(ctx context.Context, bearerToken string, level Level) (Credentials, error) {
	if err := s.validate(); err != nil {
		return Credentials{}, err
	}
	if ctx == nil {
		return Credentials{}, ErrServiceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Credentials{}, err
	}
	if !validLevel(level) {
		return Credentials{}, ErrInvalidLevel
	}
	now, err := s.currentTime()
	if err != nil {
		return Credentials{}, err
	}
	newCredentials := Credentials{}
	valid, err := s.withBearerTransaction(ctx, bearerToken, func(tx *sql.Tx, record sessionRecord) error {
		if level != LevelMFA || (record.Level != LevelEnrollmentOnly && record.Level != LevelMFAChallenge) {
			return ErrInvalidTransition
		}
		var activeFactor bool
		factorQuery := `SELECT EXISTS (
			SELECT 1 FROM registry_totp_credentials
			WHERE user_id = ` + bind(s.driver, 1) + ` AND status = 'active'
		)`
		if err := tx.QueryRowContext(ctx, factorQuery, record.UserID).Scan(&activeFactor); err != nil {
			return ErrSessionStorage
		}
		if !activeFactor {
			return ErrInvalidTransition
		}
		query := "UPDATE registry_auth_sessions SET revoked_at = " + bind(s.driver, 1) +
			" WHERE session_id = " + bind(s.driver, 2) + " AND revoked_at IS NULL"
		result, err := tx.ExecContext(ctx, query, now.Format(time.RFC3339Nano), record.ID)
		if err != nil {
			return ErrSessionStorage
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil || rowsAffected != 1 {
			return ErrSessionStorage
		}
		if err := recordAudit(ctx, tx, s.driver, record.UserID, "session.revoked", "session", record.ID, now); err != nil {
			return err
		}
		newCredentials, err = s.createInTransaction(ctx, tx, record.UserID, level, now)
		if err != nil {
			return err
		}
		return recordAudit(ctx, tx, s.driver, record.UserID, "session.created", "session", newCredentials.Session.ID, now)
	})
	if err != nil {
		return Credentials{}, err
	}
	if !valid {
		return Credentials{}, ErrSessionUnavailable
	}
	return newCredentials, nil
}

// RestrictForMFAEnrollment replaces a standard session with a short-lived
// enrollment-only session. Callers must validate CSRF and any browser-origin
// policy before requesting this transition.
func (s *Store) RestrictForMFAEnrollment(ctx context.Context, bearerToken string) (Credentials, error) {
	if err := s.validate(); err != nil {
		return Credentials{}, err
	}
	if ctx == nil {
		return Credentials{}, ErrServiceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Credentials{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return Credentials{}, err
	}
	var enrollmentCredentials Credentials
	valid, err := s.withBearerTransaction(ctx, bearerToken, func(tx *sql.Tx, record sessionRecord) error {
		if record.Level != LevelStandard {
			return ErrInvalidTransition
		}
		var activeFactor bool
		factorQuery := `SELECT EXISTS (
			SELECT 1 FROM registry_totp_credentials
			WHERE user_id = ` + bind(s.driver, 1) + ` AND status = 'active'
		)`
		if err := tx.QueryRowContext(ctx, factorQuery, record.UserID).Scan(&activeFactor); err != nil {
			return ErrSessionStorage
		}
		if activeFactor {
			return ErrInvalidTransition
		}
		query := "UPDATE registry_auth_sessions SET revoked_at = " + bind(s.driver, 1) +
			" WHERE session_id = " + bind(s.driver, 2) + " AND revoked_at IS NULL"
		result, err := tx.ExecContext(ctx, query, now.Format(time.RFC3339Nano), record.ID)
		if err != nil {
			return ErrSessionStorage
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil || rowsAffected != 1 {
			return ErrSessionStorage
		}
		if err := recordAudit(ctx, tx, s.driver, record.UserID, "session.revoked", "session", record.ID, now); err != nil {
			return err
		}
		enrollmentCredentials, err = s.createInTransaction(ctx, tx, record.UserID, LevelEnrollmentOnly, now)
		if err != nil {
			return err
		}
		return recordAudit(ctx, tx, s.driver, record.UserID, "session.created", "session", enrollmentCredentials.Session.ID, now)
	})
	if err != nil {
		return Credentials{}, err
	}
	if !valid {
		return Credentials{}, ErrSessionUnavailable
	}
	return enrollmentCredentials, nil
}

// Revoke is idempotent so logout does not reveal whether a bearer existed.
func (s *Store) Revoke(ctx context.Context, bearerToken string) error {
	if err := s.validate(); err != nil {
		return err
	}
	if ctx == nil {
		return ErrServiceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tokenHash, err := hashOpaqueToken(bearerToken)
	if err != nil {
		return nil
	}
	return s.withTransaction(ctx, func(tx *sql.Tx) error {
		var userID, sessionID string
		query := "SELECT session_id, user_id FROM registry_auth_sessions WHERE bearer_hash = " + bind(s.driver, 1)
		if err := tx.QueryRowContext(ctx, query, tokenHash).Scan(&sessionID, &userID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return ErrSessionStorage
		}
		now := s.now().UTC()
		update := "UPDATE registry_auth_sessions SET revoked_at = " + bind(s.driver, 1) +
			" WHERE session_id = " + bind(s.driver, 2) + " AND revoked_at IS NULL"
		result, err := tx.ExecContext(ctx, update, now.Format(time.RFC3339Nano), sessionID)
		if err != nil {
			return ErrSessionStorage
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return ErrSessionStorage
		}
		if rowsAffected == 1 {
			return recordAudit(ctx, tx, s.driver, userID, "session.revoked", "session", sessionID, now)
		}
		return nil
	})
}

// RevokeUserSessions invalidates every active session for an account. Account
// deactivation flows should call this in their transaction or immediately after
// changing the account state; Validate independently rejects inactive users.
func (s *Store) RevokeUserSessions(ctx context.Context, userID string) error {
	if err := s.validate(); err != nil {
		return err
	}
	if ctx == nil {
		return ErrServiceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	normalizedUserID, err := normalizeUserID(userID)
	if err != nil {
		return err
	}
	query := "UPDATE registry_auth_sessions SET revoked_at = " + bind(s.driver, 1) +
		" WHERE user_id = " + bind(s.driver, 2) + " AND revoked_at IS NULL"
	if _, err := s.db.ExecContext(ctx, query, s.now().UTC().Format(time.RFC3339Nano), normalizedUserID); err != nil {
		return ErrSessionStorage
	}
	return nil
}

func (s *Store) validateBearer(
	ctx context.Context,
	bearerToken string,
	csrfToken string,
	checkCSRF bool,
) (Session, error) {
	if err := s.validate(); err != nil {
		return Session{}, err
	}
	if ctx == nil {
		return Session{}, ErrServiceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return Session{}, err
	}
	var validatedSession Session
	valid, err := s.withBearerTransaction(ctx, bearerToken, func(tx *sql.Tx, record sessionRecord) error {
		if checkCSRF {
			csrfHash, err := hashOpaqueToken(csrfToken)
			if err != nil {
				return ErrCSRF
			}
			if subtle.ConstantTimeCompare([]byte(csrfHash), []byte(record.csrfHash)) != 1 {
				return ErrCSRF
			}
		}
		absoluteExpiry := record.AbsoluteExpiresAt
		_, idleSessionLifetime := sessionLifetimes(record.Level)
		idleExpiry := now.Add(idleSessionLifetime)
		if idleExpiry.After(absoluteExpiry) {
			idleExpiry = absoluteExpiry
		}
		query := `UPDATE registry_auth_sessions SET last_activity_at = ` + bind(s.driver, 1) +
			`, idle_expires_at = ` + bind(s.driver, 2) + ` WHERE session_id = ` + bind(s.driver, 3) +
			` AND revoked_at IS NULL`
		if _, err := tx.ExecContext(ctx, query, now.Format(time.RFC3339Nano), idleExpiry.Format(time.RFC3339Nano), record.ID); err != nil {
			return ErrSessionStorage
		}
		validatedSession = record.Session
		validatedSession.LastActivityAt = now
		validatedSession.IdleExpiresAt = idleExpiry
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	if !valid {
		return Session{}, ErrSessionUnavailable
	}
	return validatedSession, nil
}

func (s *Store) withBearerTransaction(
	ctx context.Context,
	bearerToken string,
	operation func(*sql.Tx, sessionRecord) error,
) (valid bool, retErr error) {
	if ctx == nil || operation == nil {
		return false, ErrServiceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	tokenHash, err := hashOpaqueToken(bearerToken)
	if err != nil {
		return false, ErrSessionUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, ErrSessionStorage
	}
	defer rollbackTransaction(tx, &retErr)
	userID, err := readSessionUserID(ctx, tx, s.driver, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, ErrSessionStorage
	}
	if err := lockActiveUser(ctx, tx, s.driver, userID); err != nil {
		if !errors.Is(err, ErrUserUnavailable) {
			return false, err
		}
		if err := revokeUserSessionsInTransaction(ctx, tx, s.driver, userID, s.now().UTC()); err != nil {
			return false, err
		}
		if err := tx.Commit(); err != nil {
			return false, ErrSessionStorage
		}
		return false, nil
	}
	record, err := readSession(ctx, tx, s.driver, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, ErrSessionStorage
	}
	if record.UserID != userID {
		return false, ErrSessionStorage
	}
	now := s.now().UTC()
	if record.revokedAt.Valid {
		if err := tx.Commit(); err != nil {
			return false, ErrSessionStorage
		}
		return false, nil
	}
	if !now.Before(record.AbsoluteExpiresAt) || !now.Before(record.IdleExpiresAt) {
		if err := revokeSessionInTransaction(ctx, tx, s.driver, record.ID, now); err != nil {
			return false, err
		}
		if err := tx.Commit(); err != nil {
			return false, ErrSessionStorage
		}
		return false, nil
	}
	if err := operation(tx, record); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, ErrSessionStorage
	}
	return true, nil
}

func (s *Store) createInTransaction(
	ctx context.Context,
	tx *sql.Tx,
	userID string,
	level Level,
	now time.Time,
) (Credentials, error) {
	bearerToken, err := generateOpaqueToken()
	if err != nil {
		return Credentials{}, ErrSessionStorage
	}
	csrfToken, err := generateOpaqueToken()
	if err != nil {
		return Credentials{}, ErrSessionStorage
	}
	bearerHash, err := hashOpaqueToken(bearerToken)
	if err != nil {
		return Credentials{}, ErrSessionStorage
	}
	csrfHash, err := hashOpaqueToken(csrfToken)
	if err != nil {
		return Credentials{}, ErrSessionStorage
	}
	sessionID, err := uuid.NewV7()
	if err != nil {
		return Credentials{}, ErrSessionStorage
	}
	absoluteSessionLifetime, idleSessionLifetime := sessionLifetimes(level)
	absoluteExpiry := now.Add(absoluteSessionLifetime)
	idleExpiry := now.Add(idleSessionLifetime)
	if idleExpiry.After(absoluteExpiry) {
		idleExpiry = absoluteExpiry
	}
	createdAt := now.Format(time.RFC3339Nano)
	var mfaVerifiedAt any
	var mfaTime *time.Time
	if level == LevelMFA {
		mfaVerifiedAt = createdAt
		verifiedAt := now
		mfaTime = &verifiedAt
	}
	query := `INSERT INTO registry_auth_sessions
		(session_id, user_id, bearer_hash, csrf_hash, level, created_at, last_activity_at,
		 absolute_expires_at, idle_expires_at, mfa_verified_at, revoked_at)
		VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) +
		`, ` + bind(s.driver, 5) + `, ` + bind(s.driver, 6) + `, ` + bind(s.driver, 7) + `, ` + bind(s.driver, 8) +
		`, ` + bind(s.driver, 9) + `, ` + bind(s.driver, 10) + `, NULL)`
	if _, err := tx.ExecContext(ctx, query,
		sessionID.String(), userID, bearerHash, csrfHash, string(level), createdAt, createdAt,
		absoluteExpiry.Format(time.RFC3339Nano), idleExpiry.Format(time.RFC3339Nano), mfaVerifiedAt); err != nil {
		return Credentials{}, ErrSessionStorage
	}
	return Credentials{
		BearerToken: bearerToken,
		CSRFToken:   csrfToken,
		Session: Session{
			ID:                 sessionID.String(),
			UserID:             userID,
			Level:              level,
			CreatedAt:          now,
			LastActivityAt:     now,
			AbsoluteExpiresAt:  absoluteExpiry,
			IdleExpiresAt:      idleExpiry,
			MFAAuthenticatedAt: mfaTime,
		},
	}, nil
}

func readSessionUserID(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, bearerHash string) (string, error) {
	query := "SELECT user_id FROM registry_auth_sessions WHERE bearer_hash = " + bind(driver, 1)
	var userID string
	err := tx.QueryRowContext(ctx, query, bearerHash).Scan(&userID)
	return userID, err
}

func readSession(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, bearerHash string) (sessionRecord, error) {
	query := `SELECT session_id, user_id, bearer_hash, csrf_hash, level, created_at, last_activity_at,
		absolute_expires_at, idle_expires_at, mfa_verified_at, revoked_at
		FROM registry_auth_sessions WHERE bearer_hash = ` + bind(driver, 1)
	if driver == config.Postgres {
		query += " FOR UPDATE"
	}
	var record sessionRecord
	var level string
	var createdAt, lastActivityAt, absoluteExpiry, idleExpiry string
	var mfaVerifiedAt sql.NullString
	err := tx.QueryRowContext(ctx, query, bearerHash).Scan(
		&record.ID, &record.UserID, &record.bearerHash, &record.csrfHash, &level, &createdAt,
		&lastActivityAt, &absoluteExpiry, &idleExpiry, &mfaVerifiedAt, &record.revokedAt)
	if err != nil {
		return sessionRecord{}, err
	}
	record.Level = Level(level)
	var parseErr error
	if record.CreatedAt, parseErr = parseTimestamp(createdAt); parseErr != nil {
		return sessionRecord{}, ErrSessionStorage
	}
	if record.LastActivityAt, parseErr = parseTimestamp(lastActivityAt); parseErr != nil {
		return sessionRecord{}, ErrSessionStorage
	}
	if record.AbsoluteExpiresAt, parseErr = parseTimestamp(absoluteExpiry); parseErr != nil {
		return sessionRecord{}, ErrSessionStorage
	}
	if record.IdleExpiresAt, parseErr = parseTimestamp(idleExpiry); parseErr != nil {
		return sessionRecord{}, ErrSessionStorage
	}
	if mfaVerifiedAt.Valid {
		verifiedAt, parseErr := parseTimestamp(mfaVerifiedAt.String)
		if parseErr != nil {
			return sessionRecord{}, ErrSessionStorage
		}
		record.MFAAuthenticatedAt = &verifiedAt
	}
	if !validLevel(record.Level) || (record.Level == LevelMFA) != (record.MFAAuthenticatedAt != nil) {
		return sessionRecord{}, ErrSessionStorage
	}
	return record, nil
}

func lockActiveUser(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, userID string) error {
	if driver == config.Postgres {
		var lockedUserID string
		err := tx.QueryRowContext(ctx,
			"SELECT user_id FROM registry_users WHERE user_id = $1 AND status = 'active' FOR UPDATE", userID).Scan(&lockedUserID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserUnavailable
		}
		if err != nil {
			return ErrSessionStorage
		}
		return nil
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE registry_users SET updated_at = updated_at WHERE user_id = ? AND status = 'active'", userID)
	if err != nil {
		return ErrSessionStorage
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return ErrSessionStorage
	}
	if rowsAffected != 1 {
		return ErrUserUnavailable
	}
	return nil
}

func revokeSessionInTransaction(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, sessionID string, now time.Time) error {
	query := "UPDATE registry_auth_sessions SET revoked_at = " + bind(driver, 1) +
		" WHERE session_id = " + bind(driver, 2) + " AND revoked_at IS NULL"
	if _, err := tx.ExecContext(ctx, query, now.Format(time.RFC3339Nano), sessionID); err != nil {
		return ErrSessionStorage
	}
	return nil
}

func revokeUserSessionsInTransaction(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, userID string, now time.Time) error {
	query := "UPDATE registry_auth_sessions SET revoked_at = " + bind(driver, 1) +
		" WHERE user_id = " + bind(driver, 2) + " AND revoked_at IS NULL"
	if _, err := tx.ExecContext(ctx, query, now.Format(time.RFC3339Nano), userID); err != nil {
		return ErrSessionStorage
	}
	return nil
}

func recordAudit(
	ctx context.Context,
	tx *sql.Tx,
	driver config.DatabaseDriver,
	actorID, action, targetType, targetID string,
	now time.Time,
) error {
	eventID, err := uuid.NewV7()
	if err != nil {
		return ErrSessionStorage
	}
	query := `INSERT INTO registry_audit_events
		(event_id, actor_user_id, actor_type, actor_label, action, target_type, target_id, outcome, occurred_at)
		VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, 'user', NULL, ` + bind(driver, 3) +
		`, ` + bind(driver, 4) + `, ` + bind(driver, 5) + `, 'succeeded', ` + bind(driver, 6) + `)`
	if _, err := tx.ExecContext(ctx, query, eventID.String(), actorID, action, targetType, targetID, now.Format(time.RFC3339Nano)); err != nil {
		return ErrSessionStorage
	}
	return nil
}

func (s *Store) withTransaction(ctx context.Context, operation func(*sql.Tx) error) (retErr error) {
	if operation == nil {
		return ErrServiceUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrSessionStorage
	}
	defer rollbackTransaction(tx, &retErr)
	if err := operation(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrSessionStorage
	}
	return nil
}

func rollbackTransaction(tx *sql.Tx, retErr *error) {
	if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
		*retErr = errors.Join(*retErr, ErrSessionStorage)
	}
}

func (s *Store) currentTime() (time.Time, error) {
	if err := s.validate(); err != nil {
		return time.Time{}, err
	}
	if s.now == nil {
		return time.Time{}, ErrServiceUnavailable
	}
	return s.now().UTC(), nil
}

func (s *Store) validate() error {
	if s == nil || s.db == nil || s.now == nil || (s.driver != config.SQLite && s.driver != config.Postgres) {
		return ErrServiceUnavailable
	}
	return nil
}

func generateOpaqueToken() (string, error) {
	var raw [tokenBytes]byte
	defer clear(raw[:])
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func hashOpaqueToken(token string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != tokenBytes {
		return "", ErrSessionUnavailable
	}
	defer clear(decoded)
	if base64.RawURLEncoding.EncodeToString(decoded) != token {
		return "", ErrSessionUnavailable
	}
	digest := sha256.Sum256(decoded)
	return hex.EncodeToString(digest[:]), nil
}

func parseTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func normalizeUserID(userID string) (string, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil || parsed == uuid.Nil {
		return "", ErrInvalidUser
	}
	return parsed.String(), nil
}

func validLevel(level Level) bool {
	switch level {
	case LevelEnrollmentOnly, LevelMFAChallenge, LevelStandard, LevelMFA:
		return true
	default:
		return false
	}
}

func sessionLifetimes(level Level) (time.Duration, time.Duration) {
	switch level {
	case LevelEnrollmentOnly:
		return enrollmentSessionLifetime, enrollmentSessionLifetime
	case LevelMFAChallenge:
		return mfaChallengeLifetime, mfaChallengeLifetime
	default:
		return absoluteLifetime, idleLifetime
	}
}

func bind(driver config.DatabaseDriver, position int) string {
	if driver == config.Postgres {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}
