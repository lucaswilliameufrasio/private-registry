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
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/email"
	"private-registry/internal/loginname"
)

const (
	verificationPrefix   = "prver_"
	verificationTTL      = 24 * time.Hour
	selfRecoveryTTL      = time.Hour
	selfRecoveryCooldown = 5 * time.Minute
	maxVerificationsHour = 5
)

var (
	ErrEmailUnavailable  = errors.New("email delivery is not configured on this installation")
	ErrInvalidEmail      = errors.New("email address is invalid")
	ErrVerificationLimit = errors.New("too many confirmation emails were requested; try again later")
	ErrVerificationGone  = errors.New("confirmation link is invalid, expired or already used")
	ErrNoVerifiedEmail   = errors.New("this account has no confirmed email address")
)

type mailer struct {
	queue  email.Enqueuer
	origin string
}

// EnableEmail lets the service send recovery links, address confirmations
// and security notices. origin is the registry's canonical origin; links
// point to its web interface.
func (s *Service) EnableEmail(queue email.Enqueuer, origin string) error {
	parsed, err := url.Parse(origin)
	if s == nil || queue == nil || err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return errors.New("email delivery could not be enabled")
	}
	s.mail = &mailer{queue: queue, origin: strings.TrimSuffix(origin, "/")}
	return nil
}

// EmailEnabled reports whether messages can be sent.
func (s *Service) EmailEnabled() bool { return s != nil && s.mail != nil }

func (m *mailer) link(route, token string) string {
	return m.origin + "/#/" + route + "?token=" + url.QueryEscape(token)
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") }

// AccountEmail describes a person's address and its confirmation state.
type AccountEmail struct {
	Address  string
	Verified bool
	// Pending is an address waiting for its confirmation link.
	Pending string
}

func (s *Service) AccountEmailOf(ctx context.Context, userID string) (AccountEmail, error) {
	if err := s.validate(ctx); err != nil {
		return AccountEmail{}, err
	}
	id, err := uuid.Parse(userID)
	if err != nil {
		return AccountEmail{}, ErrRejected
	}
	var result AccountEmail
	var address sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT email, email_verified FROM registry_users WHERE user_id = `+bind(s.driver, 1), id.String()).Scan(&address, &result.Verified); err != nil {
		return AccountEmail{}, ErrUnavailable
	}
	result.Address = address.String
	var pending sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT email FROM registry_email_verifications WHERE user_id = `+bind(s.driver, 1)+` AND used_at_ms IS NULL AND revoked_at_ms IS NULL AND expires_at_ms > `+bind(s.driver, 2)+` ORDER BY verification_id DESC LIMIT 1`, id.String(), time.Now().UTC().UnixMilli()).Scan(&pending)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return AccountEmail{}, ErrUnavailable
	}
	result.Pending = pending.String
	return result, nil
}

// RequestEmailVerification sends a confirmation link to address. The
// account keeps its current address until the link is used, so a typo
// cannot lock anyone out of recovery.
func (s *Service) RequestEmailVerification(ctx context.Context, userID, address string) error {
	if err := s.validate(ctx); err != nil {
		return err
	}
	if s.mail == nil {
		return ErrEmailUnavailable
	}
	id, err := uuid.Parse(userID)
	if err != nil {
		return ErrRejected
	}
	address = strings.TrimSpace(address)
	if !email.ValidAddress(address) {
		return ErrInvalidEmail
	}
	verificationID, err := uuid.NewV7()
	if err != nil {
		return ErrUnavailable
	}
	token, digest, err := newLinkToken(verificationPrefix, verificationID)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	return s.withTransaction(ctx, func(tx *sql.Tx) error {
		var display, status string
		var service bool
		if err := tx.QueryRowContext(ctx, `SELECT u.display_name, u.status, EXISTS (SELECT 1 FROM registry_service_accounts a WHERE a.user_id = u.user_id) FROM registry_users u WHERE u.user_id = `+bind(s.driver, 1), id.String()).Scan(&display, &status, &service); err != nil {
			return ErrUnavailable
		}
		if status != "active" || service {
			return ErrRejected
		}
		var recent int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_email_verifications WHERE user_id = `+bind(s.driver, 1)+` AND created_at_ms > `+bind(s.driver, 2), id.String(), now.Add(-time.Hour).UnixMilli()).Scan(&recent); err != nil {
			return ErrUnavailable
		}
		if recent >= maxVerificationsHour {
			return ErrVerificationLimit
		}
		if _, err := tx.ExecContext(ctx, `UPDATE registry_email_verifications SET revoked_at_ms = `+bind(s.driver, 1)+` WHERE user_id = `+bind(s.driver, 2)+` AND used_at_ms IS NULL AND revoked_at_ms IS NULL`, now.UnixMilli(), id.String()); err != nil {
			return ErrUnavailable
		}
		expires := now.Add(verificationTTL)
		if _, err := tx.ExecContext(ctx, `INSERT INTO registry_email_verifications (verification_id, user_id, email, token_sha256, created_at_ms, expires_at_ms) VALUES (`+bind(s.driver, 1)+`, `+bind(s.driver, 2)+`, `+bind(s.driver, 3)+`, `+bind(s.driver, 4)+`, `+bind(s.driver, 5)+`, `+bind(s.driver, 6)+`)`, verificationID.String(), id.String(), address, digest, now.UnixMilli(), expires.UnixMilli()); err != nil {
			return ErrUnavailable
		}
		message := email.Message{Template: email.TemplateEmailVerification, To: address, Data: map[string]string{"display_name": display, "link": s.mail.link("verify-email", token), "expires_at": stamp(expires)}}
		if err := s.mail.queue.EnqueueTx(ctx, tx, "verification:"+verificationID.String(), message); err != nil {
			return ErrUnavailable
		}
		return s.recordRecoveryAudit(ctx, tx, id.String(), "", "account.email.verification_requested", id.String())
	})
}

// ConfirmEmail uses a confirmation link: the address becomes the account's
// confirmed address. A previously confirmed address is told about the
// change. The link alone is enough, so it works from another device.
func (s *Service) ConfirmEmail(ctx context.Context, token string) error {
	if err := s.validate(ctx); err != nil {
		return err
	}
	idText, digest, ok := parseLinkToken(verificationPrefix, token)
	if !ok {
		return ErrVerificationGone
	}
	return s.withTransaction(ctx, func(tx *sql.Tx) error {
		var userID, address, storedHash string
		var expires int64
		var used, revoked sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT user_id, email, token_sha256, expires_at_ms, used_at_ms, revoked_at_ms FROM registry_email_verifications WHERE verification_id = `+bind(s.driver, 1), idText).Scan(&userID, &address, &storedHash, &expires, &used, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrVerificationGone
		} else if err != nil {
			return ErrUnavailable
		}
		now := time.Now().UTC()
		if !hashMatches(storedHash, digest) || used.Valid || revoked.Valid || now.UnixMilli() >= expires {
			return ErrVerificationGone
		}
		var display, status string
		var previous sql.NullString
		var previousVerified bool
		if err := tx.QueryRowContext(ctx, `SELECT display_name, status, email, email_verified FROM registry_users WHERE user_id = `+bind(s.driver, 1), userID).Scan(&display, &status, &previous, &previousVerified); err != nil || status != "active" {
			return ErrVerificationGone
		}
		if _, err := tx.ExecContext(ctx, `UPDATE registry_email_verifications SET used_at_ms = `+bind(s.driver, 1)+` WHERE verification_id = `+bind(s.driver, 2), now.UnixMilli(), idText); err != nil {
			return ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, `UPDATE registry_users SET email = `+bind(s.driver, 1)+`, email_verified = TRUE, updated_at = `+bind(s.driver, 2)+` WHERE user_id = `+bind(s.driver, 3), address, now.Format(time.RFC3339Nano), userID); err != nil {
			return ErrUnavailable
		}
		if previousVerified && previous.Valid && !strings.EqualFold(previous.String, address) {
			if err := s.notify(ctx, tx, "email-changed:"+idText, previous.String, display, "endereço de e-mail da conta alterado", now); err != nil {
				return err
			}
		}
		return s.recordRecoveryAudit(ctx, tx, userID, "", "account.email.verified", userID)
	})
}

// RequestRecovery is the "forgot my password" path. It never reveals whether
// the login name exists: it returns nil for unknown accounts, accounts
// without a confirmed address and repeated requests. A link it sends sets a
// new password only; second factors stay required at the next sign-in.
func (s *Service) RequestRecovery(ctx context.Context, loginName string) error {
	if err := s.validate(ctx); err != nil {
		return err
	}
	if s.mail == nil {
		return ErrEmailUnavailable
	}
	normalized := loginname.Normalize(loginName)
	if !loginname.Valid(normalized) {
		return nil
	}
	resetID, err := uuid.NewV7()
	if err != nil {
		return ErrUnavailable
	}
	token, digest, err := newLinkToken(recoveryPrefix, resetID)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	return s.withTransaction(ctx, func(tx *sql.Tx) error {
		var userID, display string
		var address sql.NullString
		var verified bool
		err := tx.QueryRowContext(ctx, `SELECT u.user_id, u.display_name, u.email, u.email_verified FROM registry_local_credentials c JOIN registry_users u ON u.user_id = c.user_id WHERE c.login_name = `+bind(s.driver, 1)+` AND u.status = 'active' AND NOT EXISTS (SELECT 1 FROM registry_service_accounts a WHERE a.user_id = u.user_id)`, normalized).Scan(&userID, &display, &address, &verified)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return ErrUnavailable
		}
		if !verified || !address.Valid || !email.ValidAddress(address.String) {
			return nil
		}
		var recent int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_password_resets WHERE user_id = `+bind(s.driver, 1)+` AND self_requested = 1 AND created_at_ms > `+bind(s.driver, 2), userID, now.Add(-selfRecoveryCooldown).UnixMilli()).Scan(&recent); err != nil {
			return ErrUnavailable
		}
		if recent > 0 {
			return nil
		}
		// Only earlier self-requested links stop working: anyone who knows
		// the login name must not be able to cancel a link an administrator
		// issued.
		if _, err := tx.ExecContext(ctx, `UPDATE registry_password_resets SET revoked_at_ms = `+bind(s.driver, 1)+` WHERE user_id = `+bind(s.driver, 2)+` AND self_requested = 1 AND used_at_ms IS NULL AND revoked_at_ms IS NULL`, now.UnixMilli(), userID); err != nil {
			return ErrUnavailable
		}
		expires := now.Add(selfRecoveryTTL)
		if _, err := tx.ExecContext(ctx, `INSERT INTO registry_password_resets (reset_id, user_id, token_sha256, reset_mfa, self_requested, created_at_ms, expires_at_ms) VALUES (`+bind(s.driver, 1)+`, `+bind(s.driver, 2)+`, `+bind(s.driver, 3)+`, 0, 1, `+bind(s.driver, 4)+`, `+bind(s.driver, 5)+`)`, resetID.String(), userID, digest, now.UnixMilli(), expires.UnixMilli()); err != nil {
			return ErrUnavailable
		}
		message := email.Message{Template: email.TemplateRecovery, To: address.String, Data: map[string]string{"display_name": display, "link": s.mail.link("recover", token), "expires_at": stamp(expires)}}
		if err := s.mail.queue.EnqueueTx(ctx, tx, "recovery:"+resetID.String(), message); err != nil {
			return ErrUnavailable
		}
		return s.recordRecoveryAudit(ctx, tx, userID, "", "account.recovery.requested", userID)
	})
}

// notify queues a security notice when email is enabled. key names the
// event, so the notice is sent once.
func (s *Service) notify(ctx context.Context, tx *sql.Tx, key, address, display, event string, at time.Time) error {
	if s.mail == nil || !email.ValidAddress(address) {
		return nil
	}
	message := email.Message{Template: email.TemplateSecurityNotice, To: address, Data: map[string]string{"display_name": display, "event_label": event, "occurred_at": stamp(at), "registry_url": s.mail.origin}}
	// A notice must never block the change it reports.
	if message.Validate() != nil {
		return nil
	}
	if err := s.mail.queue.EnqueueTx(ctx, tx, "notice:"+key, message); err != nil {
		return ErrUnavailable
	}
	return nil
}

// notifyUser sends a security notice to the user's confirmed address, if any.
func (s *Service) notifyUser(ctx context.Context, tx *sql.Tx, key, userID, event string, at time.Time) error {
	if s.mail == nil {
		return nil
	}
	var display string
	var address sql.NullString
	var verified bool
	if err := tx.QueryRowContext(ctx, `SELECT display_name, email, email_verified FROM registry_users WHERE user_id = `+bind(s.driver, 1), userID).Scan(&display, &address, &verified); err != nil {
		return ErrUnavailable
	}
	if !verified || !address.Valid {
		return nil
	}
	return s.notify(ctx, tx, key, address.String, display, event, at)
}

func newLinkToken(prefix string, id uuid.UUID) (string, string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", "", ErrUnavailable
	}
	defer clear(secret[:])
	digest := sha256.Sum256(secret[:])
	return prefix + id.String() + "." + base64.RawURLEncoding.EncodeToString(secret[:]), hex.EncodeToString(digest[:]), nil
}

func parseLinkToken(prefix, token string) (string, [32]byte, bool) {
	idText, encoded, found := strings.Cut(strings.TrimPrefix(token, prefix), ".")
	parsed, err := uuid.Parse(idText)
	if !strings.HasPrefix(token, prefix) || !found || err != nil || parsed.String() != idText || len(encoded) != 43 {
		return "", [32]byte{}, false
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(secret) != 32 {
		return "", [32]byte{}, false
	}
	defer clear(secret)
	return idText, sha256.Sum256(secret), true
}

func hashMatches(stored string, digest [32]byte) bool {
	decoded, err := hex.DecodeString(stored)
	return err == nil && len(decoded) == sha256.Size && subtle.ConstantTimeCompare(decoded, digest[:]) == 1
}
