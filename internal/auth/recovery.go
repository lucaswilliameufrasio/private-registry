package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/bootstrap"
	"private-registry/internal/database"
	"private-registry/internal/loginname"
	"private-registry/internal/password"
)

const (
	recoveryPrefix = "prrst_"
	recoveryTTL    = 24 * time.Hour
)

var (
	ErrRecoveryUnavailable = errors.New("recovery link is invalid, expired or already used")
	ErrRecoveryTarget      = errors.New("this account cannot be recovered here")
	ErrRecoveryForbidden   = errors.New("only installation administrators can recover other accounts")
	ErrRecoveryPassword    = errors.New("the new password does not meet the requirements")
)

type IssuedRecovery struct {
	ID        string
	ExpiresAt time.Time
	ResetMFA  bool
	// Token is shown once and never stored.
	Token string
}

// IssueRecovery lets an installation administrator start the recovery of
// another account: a single-use link, valid 24 hours, that sets a new local
// password and, when resetMFA is set, removes the account's second factors so
// the next sign-in enrolls new ones. It never creates a session. Earlier
// unused links for the account stop working.
func (s *Service) IssueRecovery(ctx context.Context, actorUserID, targetUserID string, resetMFA bool) (IssuedRecovery, error) {
	if err := s.validate(ctx); err != nil {
		return IssuedRecovery{}, err
	}
	actor, err := uuid.Parse(actorUserID)
	if err != nil {
		return IssuedRecovery{}, ErrRejected
	}
	target, err := uuid.Parse(targetUserID)
	if err != nil {
		return IssuedRecovery{}, ErrRecoveryTarget
	}
	if actor == target {
		return IssuedRecovery{}, ErrRecoveryTarget
	}
	id, err := uuid.NewV7()
	if err != nil {
		return IssuedRecovery{}, ErrUnavailable
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return IssuedRecovery{}, ErrUnavailable
	}
	defer clear(secret[:])
	digest := sha256.Sum256(secret[:])
	now := time.Now().UTC().Truncate(time.Millisecond)
	issued := IssuedRecovery{ID: id.String(), ExpiresAt: now.Add(recoveryTTL), ResetMFA: resetMFA, Token: recoveryPrefix + id.String() + "." + base64.RawURLEncoding.EncodeToString(secret[:])}
	err = s.withTransaction(ctx, func(tx *sql.Tx) error {
		var admin bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_instance_admins a JOIN registry_users u ON u.user_id = a.user_id WHERE a.user_id = `+bind(s.driver, 1)+` AND u.status = 'active')`, actor.String()).Scan(&admin); err != nil {
			return ErrUnavailable
		}
		if !admin {
			return ErrRecoveryForbidden
		}
		var status string
		var service, local bool
		err := tx.QueryRowContext(ctx, `SELECT u.status, EXISTS (SELECT 1 FROM registry_service_accounts a WHERE a.user_id = u.user_id), EXISTS (SELECT 1 FROM registry_local_credentials c WHERE c.user_id = u.user_id) FROM registry_users u WHERE u.user_id = `+bind(s.driver, 1), target.String()).Scan(&status, &service, &local)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRecoveryTarget
		} else if err != nil {
			return ErrUnavailable
		}
		// Service accounts have nothing to recover. Accounts without a local
		// password recover their sign-in at their identity provider; only
		// their local second factors can be reset here.
		if service || status != "active" || (!local && !resetMFA) {
			return ErrRecoveryTarget
		}
		if _, err := tx.ExecContext(ctx, `UPDATE registry_password_resets SET revoked_at_ms = `+bind(s.driver, 1)+` WHERE user_id = `+bind(s.driver, 2)+` AND used_at_ms IS NULL AND revoked_at_ms IS NULL`, now.UnixMilli(), target.String()); err != nil {
			return ErrUnavailable
		}
		flag := 0
		if resetMFA {
			flag = 1
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO registry_password_resets (reset_id, user_id, token_sha256, reset_mfa, created_by, created_at_ms, expires_at_ms) VALUES (`+bind(s.driver, 1)+`, `+bind(s.driver, 2)+`, `+bind(s.driver, 3)+`, `+bind(s.driver, 4)+`, `+bind(s.driver, 5)+`, `+bind(s.driver, 6)+`, `+bind(s.driver, 7)+`)`, issued.ID, target.String(), hex.EncodeToString(digest[:]), flag, actor.String(), now.UnixMilli(), issued.ExpiresAt.UnixMilli()); err != nil {
			return ErrUnavailable
		}
		return s.recordRecoveryAudit(ctx, tx, actor.String(), "", "account.recovery.issued", target.String())
	})
	if err != nil {
		return IssuedRecovery{}, err
	}
	return issued, nil
}

// CompleteRecovery uses a recovery link. newPassword is required for
// accounts with a local password and refused for the others. Every session
// of the account is revoked; the person then signs in normally.
func (s *Service) CompleteRecovery(ctx context.Context, token string, newPassword []byte) error {
	if err := s.validate(ctx); err != nil {
		return err
	}
	idText, encoded, found := strings.Cut(strings.TrimPrefix(token, recoveryPrefix), ".")
	parsed, err := uuid.Parse(idText)
	if !strings.HasPrefix(token, recoveryPrefix) || !found || err != nil || parsed.String() != idText || len(encoded) != 43 {
		return ErrRecoveryUnavailable
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(secret) != 32 {
		return ErrRecoveryUnavailable
	}
	defer clear(secret)
	digest := sha256.Sum256(secret)
	var hash string
	if len(newPassword) > 0 {
		if _, _, err := bootstrap.ValidateLocalAccount("recovery.check", "Recovery", newPassword); err != nil {
			return ErrRecoveryPassword
		}
		select {
		case passwordHashAdmission <- struct{}{}:
			hash, err = password.Hash(newPassword)
			<-passwordHashAdmission
		default:
			return ErrBusy
		}
		if err != nil {
			return ErrUnavailable
		}
	}
	return s.withTransaction(ctx, func(tx *sql.Tx) error {
		var userID, storedHash string
		var resetMFA int
		var expires int64
		var used, revoked sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT user_id, token_sha256, reset_mfa, expires_at_ms, used_at_ms, revoked_at_ms FROM registry_password_resets WHERE reset_id = `+bind(s.driver, 1), idText).Scan(&userID, &storedHash, &resetMFA, &expires, &used, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRecoveryUnavailable
		} else if err != nil {
			return ErrUnavailable
		}
		stored, err := hex.DecodeString(storedHash)
		now := time.Now().UTC()
		if err != nil || subtle.ConstantTimeCompare(stored, digest[:]) != 1 || used.Valid || revoked.Valid || now.UnixMilli() >= expires {
			return ErrRecoveryUnavailable
		}
		var status string
		var local bool
		if err := tx.QueryRowContext(ctx, `SELECT u.status, EXISTS (SELECT 1 FROM registry_local_credentials c WHERE c.user_id = u.user_id) FROM registry_users u WHERE u.user_id = `+bind(s.driver, 1), userID).Scan(&status, &local); err != nil || status != "active" {
			return ErrRecoveryUnavailable
		}
		if local != (hash != "") {
			if local {
				return ErrRecoveryPassword
			}
			return ErrRecoveryTarget
		}
		result, err := tx.ExecContext(ctx, `UPDATE registry_password_resets SET used_at_ms = `+bind(s.driver, 1)+` WHERE reset_id = `+bind(s.driver, 2)+` AND used_at_ms IS NULL AND revoked_at_ms IS NULL`, now.UnixMilli(), idText)
		if err != nil {
			return ErrUnavailable
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrRecoveryUnavailable
		}
		if err := s.applyRecovery(ctx, tx, userID, hash, resetMFA == 1, now); err != nil {
			return err
		}
		return s.recordRecoveryAudit(ctx, tx, userID, "", "account.recovery.completed", userID)
	})
}

// RecoverAdministrator is for the local operator only (registry
// recover-admin): it sets a new password for an existing installation
// administrator, removes their second factors and revokes their sessions.
func (s *Service) RecoverAdministrator(ctx context.Context, loginName string, newPassword []byte, operator string) error {
	if err := s.validate(ctx); err != nil {
		return err
	}
	normalized := loginname.Normalize(loginName)
	if !loginname.Valid(normalized) || strings.TrimSpace(operator) == "" {
		return ErrRecoveryTarget
	}
	if _, _, err := bootstrap.ValidateLocalAccount("recovery.check", "Recovery", newPassword); err != nil {
		return ErrRecoveryPassword
	}
	hash, err := password.Hash(newPassword)
	if err != nil {
		return ErrUnavailable
	}
	return s.withTransaction(ctx, func(tx *sql.Tx) error {
		var userID string
		err := tx.QueryRowContext(ctx, `SELECT c.user_id FROM registry_local_credentials c JOIN registry_instance_admins a ON a.user_id = c.user_id JOIN registry_users u ON u.user_id = c.user_id WHERE c.login_name = `+bind(s.driver, 1)+` AND u.status = 'active'`, normalized).Scan(&userID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRecoveryTarget
		} else if err != nil {
			return ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, `UPDATE registry_password_resets SET revoked_at_ms = `+bind(s.driver, 1)+` WHERE user_id = `+bind(s.driver, 2)+` AND used_at_ms IS NULL AND revoked_at_ms IS NULL`, time.Now().UTC().UnixMilli(), userID); err != nil {
			return ErrUnavailable
		}
		if err := s.applyRecovery(ctx, tx, userID, hash, true, time.Now().UTC()); err != nil {
			return err
		}
		return s.recordRecoveryAudit(ctx, tx, "", operator, "instance_admin.recovered", userID)
	})
}

func (s *Service) applyRecovery(ctx context.Context, tx *sql.Tx, userID, hash string, resetMFA bool, now time.Time) error {
	stamp := now.Format(time.RFC3339Nano)
	if hash != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE registry_local_credentials SET password_hash = `+bind(s.driver, 1)+`, updated_at = `+bind(s.driver, 2)+`, password_changed_at = `+bind(s.driver, 3)+` WHERE user_id = `+bind(s.driver, 4), hash, stamp, stamp, userID); err != nil {
			return ErrUnavailable
		}
	}
	if resetMFA {
		for _, query := range []string{
			`DELETE FROM registry_mfa_recovery_codes WHERE user_id = ` + bind(s.driver, 1),
			`DELETE FROM registry_totp_credentials WHERE user_id = ` + bind(s.driver, 1),
			`DELETE FROM registry_webauthn_credentials WHERE user_id = ` + bind(s.driver, 1),
		} {
			if _, err := tx.ExecContext(ctx, query, userID); err != nil {
				return ErrUnavailable
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE registry_auth_sessions SET revoked_at = `+bind(s.driver, 1)+` WHERE user_id = `+bind(s.driver, 2)+` AND revoked_at IS NULL`, stamp, userID); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) recordRecoveryAudit(ctx context.Context, tx *sql.Tx, actor, operator, action, target string) error {
	eventID, err := uuid.NewV7()
	if err != nil {
		return ErrUnavailable
	}
	var actorValue, labelValue any
	actorType := "user"
	if actor != "" {
		actorValue = actor
	} else {
		actorType = "operator"
		labelValue = operator
	}
	query := `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, actor_label, action, target_type, target_id, outcome, occurred_at) VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `, 'user', ` + bind(s.driver, 6) + `, 'succeeded', ` + bind(s.driver, 7) + `)`
	if _, err := tx.ExecContext(ctx, query, eventID.String(), actorValue, actorType, labelValue, action, target, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) withTransaction(ctx context.Context, operation func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	if err := database.ReserveWrite(ctx, tx, s.driver); err != nil {
		_ = tx.Rollback()
		return ErrUnavailable
	}
	if err := operation(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}
