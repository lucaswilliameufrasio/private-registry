package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"private-registry/internal/authattempts"
	"private-registry/internal/config"
	"private-registry/internal/loginname"
	"private-registry/internal/mfa"
	"private-registry/internal/password"
	"private-registry/internal/secrets"
	"private-registry/internal/sessions"
)

const (
	maxLoginNameBytes           = 256
	maxConcurrentPasswordChecks = 2
)

type Stage string

const (
	StageAuthenticated Stage = "authenticated"
	StageMFAChallenge  Stage = "mfa_challenge"
	StageMFAEnrollment Stage = "mfa_enrollment"
)

var (
	ErrUnavailable           = errors.New("authentication is temporarily unavailable")
	ErrBusy                  = errors.New("authentication capacity is temporarily full")
	ErrRejected              = errors.New("credentials or authentication code were rejected")
	ErrRateLimited           = authattempts.ErrRateLimited
	ErrInvalidClientAddress  = authattempts.ErrInvalidSource
	ErrEnrollmentUnavailable = errors.New("MFA enrollment is not available")
)

type Result struct {
	Stage       Stage
	Credentials sessions.Credentials
}

type EnrollmentCompletion struct {
	Credentials   sessions.Credentials
	RecoveryCodes []string
}

type accountRecord struct {
	userID       string
	status       string
	passwordHash string
	requiresMFA  bool
}

type Service struct {
	db       *sql.DB
	driver   config.DatabaseDriver
	mfa      *mfa.Service
	sessions *sessions.Store
	attempts *authattempts.Limiter
	verify   func(string, []byte) bool
}

var passwordHashAdmission = make(chan struct{}, maxConcurrentPasswordChecks)

func New(db *sql.DB, driver config.DatabaseDriver, key *secrets.MasterKey) (*Service, error) {
	if db == nil || key == nil || (driver != config.SQLite && driver != config.Postgres) {
		return nil, ErrUnavailable
	}
	mfaService, err := mfa.New(db, driver, key)
	if err != nil {
		return nil, ErrUnavailable
	}
	sessionStore, err := sessions.New(db, driver)
	if err != nil {
		return nil, ErrUnavailable
	}
	attemptLimiter, err := authattempts.New(db, driver)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Service{
		db:       db,
		driver:   driver,
		mfa:      mfaService,
		sessions: sessionStore,
		attempts: attemptLimiter,
		verify:   password.Verify,
	}, nil
}

// Login verifies a local username/password pair and returns the next restricted
// authentication stage. The source address must come from the accepted network
// peer; a future HTTP adapter may use forwarded headers only from configured
// trusted proxies. This method does not create or expose an HTTP route.
func (s *Service) Login(ctx context.Context, loginName string, passwordValue []byte, sourceAddress string) (Result, error) {
	if err := s.validate(ctx); err != nil {
		return Result{}, err
	}
	identity, validLoginName := normalizedLogin(loginName)
	if _, err := s.attempts.BeginPassword(ctx, identity, sourceAddress); err != nil {
		if errors.Is(err, authattempts.ErrRateLimited) {
			return Result{}, ErrRateLimited
		}
		if errors.Is(err, authattempts.ErrInvalidSource) {
			return Result{}, ErrInvalidClientAddress
		}
		return Result{}, ErrUnavailable
	}
	if len(passwordValue) > password.MaxPasswordBytes {
		return Result{}, ErrRejected
	}
	select {
	case passwordHashAdmission <- struct{}{}:
		defer func() {
			<-passwordHashAdmission
		}()
	default:
		return Result{}, ErrBusy
	}

	var account accountRecord
	found := false
	if validLoginName {
		var err error
		account, found, err = s.findLocalAccount(ctx, identity)
		if err != nil {
			return Result{}, ErrUnavailable
		}
	}
	encodedHash := ""
	if found {
		encodedHash = account.passwordHash
	}
	passwordMatches := s.verify(encodedHash, passwordValue)
	if !found || !validLoginName || !passwordMatches || account.status != "active" {
		return Result{}, ErrRejected
	}
	if err := s.attempts.CompletePassword(ctx, identity); err != nil {
		return Result{}, ErrUnavailable
	}

	hasFactor, err := s.mfa.HasActiveFactor(ctx, account.userID)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	if account.requiresMFA || hasFactor {
		level := sessions.LevelMFAChallenge
		stage := StageMFAChallenge
		if !hasFactor {
			level = sessions.LevelEnrollmentOnly
			stage = StageMFAEnrollment
		}
		credentials, err := s.sessions.Create(ctx, account.userID, level)
		if err != nil {
			return Result{}, ErrUnavailable
		}
		return Result{Stage: stage, Credentials: credentials}, nil
	}
	credentials, err := s.sessions.Create(ctx, account.userID, sessions.LevelStandard)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	return Result{Stage: StageAuthenticated, Credentials: credentials}, nil
}

func (s *Service) BeginMFAEnrollment(ctx context.Context, bearerToken string) (mfa.Enrollment, error) {
	session, err := s.validateRestrictedSession(ctx, bearerToken, sessions.LevelEnrollmentOnly)
	if err != nil {
		return mfa.Enrollment{}, err
	}
	enrollment, err := s.mfa.BeginEnrollment(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, mfa.ErrEnrollmentExpired) {
			return mfa.Enrollment{}, ErrEnrollmentUnavailable
		}
		return mfa.Enrollment{}, ErrUnavailable
	}
	return enrollment, nil
}

func (s *Service) CompleteMFAEnrollment(
	ctx context.Context,
	bearerToken string,
	code string,
	sourceAddress string,
) (EnrollmentCompletion, error) {
	session, err := s.validateRestrictedSession(ctx, bearerToken, sessions.LevelEnrollmentOnly)
	if err != nil {
		return EnrollmentCompletion{}, err
	}
	if _, err := s.attempts.BeginMFA(ctx, session.UserID, sourceAddress); err != nil {
		if errors.Is(err, authattempts.ErrRateLimited) {
			return EnrollmentCompletion{}, ErrRateLimited
		}
		if errors.Is(err, authattempts.ErrInvalidSource) {
			return EnrollmentCompletion{}, ErrInvalidClientAddress
		}
		return EnrollmentCompletion{}, ErrUnavailable
	}
	recoveryCodes, err := s.mfa.ConfirmEnrollment(ctx, session.UserID, code)
	if err != nil {
		if errors.Is(err, mfa.ErrInvalidCode) {
			return EnrollmentCompletion{}, ErrRejected
		}
		return EnrollmentCompletion{}, ErrEnrollmentUnavailable
	}
	if err := s.attempts.CompleteMFA(ctx, session.UserID); err != nil {
		return EnrollmentCompletion{}, ErrUnavailable
	}
	credentials, err := s.sessions.Rotate(ctx, bearerToken, sessions.LevelMFA)
	if err != nil {
		return EnrollmentCompletion{}, ErrUnavailable
	}
	return EnrollmentCompletion{Credentials: credentials, RecoveryCodes: recoveryCodes}, nil
}

func (s *Service) CompleteMFA(ctx context.Context, bearerToken, code, sourceAddress string) (sessions.Credentials, error) {
	session, err := s.validateRestrictedSession(ctx, bearerToken, sessions.LevelMFAChallenge)
	if err != nil {
		return sessions.Credentials{}, err
	}
	if _, err := s.attempts.BeginMFA(ctx, session.UserID, sourceAddress); err != nil {
		if errors.Is(err, authattempts.ErrRateLimited) {
			return sessions.Credentials{}, ErrRateLimited
		}
		if errors.Is(err, authattempts.ErrInvalidSource) {
			return sessions.Credentials{}, ErrInvalidClientAddress
		}
		return sessions.Credentials{}, ErrUnavailable
	}
	verified, err := s.mfa.VerifyTOTP(ctx, session.UserID, code)
	if err != nil {
		return sessions.Credentials{}, ErrUnavailable
	}
	if !verified {
		verified, err = s.mfa.ConsumeRecoveryCode(ctx, session.UserID, code)
		if err != nil {
			return sessions.Credentials{}, ErrUnavailable
		}
	}
	if !verified {
		return sessions.Credentials{}, ErrRejected
	}
	if err := s.attempts.CompleteMFA(ctx, session.UserID); err != nil {
		return sessions.Credentials{}, ErrUnavailable
	}
	credentials, err := s.sessions.Rotate(ctx, bearerToken, sessions.LevelMFA)
	if err != nil {
		return sessions.Credentials{}, ErrUnavailable
	}
	return credentials, nil
}

// ValidateWithCSRF validates a browser session and its synchronizer token. The
// HTTP boundary must additionally validate the configured Origin before writes.
func (s *Service) ValidateWithCSRF(ctx context.Context, bearerToken, csrfToken string) (sessions.Session, error) {
	if err := s.validate(ctx); err != nil {
		return sessions.Session{}, err
	}
	session, err := s.sessions.ValidateWithCSRF(ctx, bearerToken, csrfToken)
	if err != nil {
		return sessions.Session{}, err
	}
	return session, nil
}

// Logout revokes the supplied opaque bearer without revealing whether it was
// already absent or revoked.
func (s *Service) Logout(ctx context.Context, bearerToken string) error {
	if err := s.validate(ctx); err != nil {
		return err
	}
	if err := s.sessions.Revoke(ctx, bearerToken); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) validateRestrictedSession(ctx context.Context, bearerToken string, requiredLevel sessions.Level) (sessions.Session, error) {
	if err := s.validate(ctx); err != nil {
		return sessions.Session{}, err
	}
	session, err := s.sessions.Validate(ctx, bearerToken)
	if err != nil {
		if errors.Is(err, sessions.ErrSessionUnavailable) {
			return sessions.Session{}, ErrRejected
		}
		return sessions.Session{}, ErrUnavailable
	}
	if session.Level != requiredLevel {
		return sessions.Session{}, ErrRejected
	}
	return session, nil
}

func (s *Service) findLocalAccount(ctx context.Context, normalizedName string) (accountRecord, bool, error) {
	if ctx == nil || len(normalizedName) > 63 {
		return accountRecord{}, false, ErrUnavailable
	}
	query := `SELECT users.user_id, users.status, credentials.password_hash,
		(EXISTS (
			SELECT 1 FROM registry_instance_admins AS admins
			WHERE admins.user_id = users.user_id
		) OR EXISTS (
			SELECT 1 FROM registry_workspace_memberships AS memberships
			JOIN registry_workspaces AS workspaces ON workspaces.workspace_id = memberships.workspace_id
			WHERE memberships.user_id = users.user_id
				AND memberships.role IN ('owner', 'administrator')
				AND memberships.status = 'active'
				AND workspaces.status = 'active'
		))
		FROM registry_local_credentials AS credentials
		JOIN registry_users AS users ON users.user_id = credentials.user_id
		WHERE credentials.login_name = ` + bind(s.driver, 1)
	var account accountRecord
	err := s.db.QueryRowContext(ctx, query, normalizedName).Scan(
		&account.userID, &account.status, &account.passwordHash, &account.requiresMFA)
	if errors.Is(err, sql.ErrNoRows) {
		return accountRecord{}, false, nil
	}
	if err != nil {
		return accountRecord{}, false, err
	}
	if _, err := uuid.Parse(account.userID); err != nil {
		return accountRecord{}, false, errors.New("local account identity is invalid")
	}
	return account, true, nil
}

func (s *Service) validate(ctx context.Context) error {
	if s == nil || s.db == nil || s.mfa == nil || s.sessions == nil || s.attempts == nil || s.verify == nil ||
		(s.driver != config.SQLite && s.driver != config.Postgres) || ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func normalizedLogin(value string) (string, bool) {
	if len(value) > maxLoginNameBytes {
		return "<invalid-login>", false
	}
	normalized := loginname.Normalize(value)
	if !loginname.Valid(normalized) {
		return "<invalid-login>", false
	}
	return normalized, true
}

func bind(driver config.DatabaseDriver, position int) string {
	if driver == config.Postgres {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}
