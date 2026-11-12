package auth

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"private-registry/internal/sessions"
)

const (
	passkeyCeremonyLifetime = 5 * time.Minute
	passkeyStateContext     = "private-registry/passkey-ceremony/v1"
	maxPasskeysPerUser      = 20
)

var (
	ErrPasskeysDisabled = errors.New("passkeys are not configured")
	ErrPasskeyRejected  = errors.New("passkey was rejected")
	ErrPasskeyLimit     = errors.New("account already holds the maximum number of passkeys")
	ErrPasskeyUnknown   = errors.New("passkey is unknown")
)

// Passkey is the stored metadata of one credential.
type Passkey struct {
	ID         string
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

type passkeyUser struct {
	id          uuid.UUID
	name        string
	credentials []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                         { return u.id[:] }
func (u passkeyUser) WebAuthnName() string                       { return u.name }
func (u passkeyUser) WebAuthnDisplayName() string                { return u.name }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

type passkeyCeremony struct {
	Purpose string               `json:"p"`
	UserID  string               `json:"u,omitempty"`
	Name    string               `json:"n,omitempty"`
	Session webauthn.SessionData `json:"s"`
}

// EnablePasskeys configures the relying party: the registry's canonical
// origin. Credentials registered under one origin only work there.
func (s *Service) EnablePasskeys(canonicalOrigin string) error {
	if s == nil || s.key == nil || !strings.HasPrefix(canonicalOrigin, "https://") {
		return errors.New("passkey configuration is invalid")
	}
	parsed, err := url.Parse(canonicalOrigin)
	if err != nil || parsed.Hostname() == "" {
		return errors.New("passkey configuration is invalid")
	}
	host := parsed.Hostname()
	// WebAuthn binds credentials to a domain; an origin addressed by IP
	// cannot hold passkeys, so they stay unavailable there.
	if net.ParseIP(host) != nil {
		return ErrPasskeysDisabled
	}
	relyingParty, err := webauthn.New(&webauthn.Config{
		RPID:          host,
		RPDisplayName: "Private Registry",
		RPOrigins:     []string{canonicalOrigin},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyCeremonyLifetime},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyCeremonyLifetime},
		},
	})
	if err != nil {
		return errors.Join(errors.New("passkey configuration is invalid"), err)
	}
	s.passkeys = relyingParty
	return nil
}

func (s *Service) PasskeysEnabled() bool { return s != nil && s.passkeys != nil }

func (s *Service) sealCeremony(ceremony passkeyCeremony) (string, error) {
	plaintext, err := json.Marshal(ceremony)
	if err != nil {
		return "", ErrUnavailable
	}
	defer clear(plaintext)
	sealed, err := s.key.Seal(plaintext, []byte(passkeyStateContext))
	if err != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Service) openCeremony(sealed, purpose string) (passkeyCeremony, error) {
	if sealed == "" || len(sealed) > 8192 {
		return passkeyCeremony{}, ErrPasskeyRejected
	}
	envelope, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return passkeyCeremony{}, ErrPasskeyRejected
	}
	plaintext, err := s.key.Open(envelope, []byte(passkeyStateContext))
	if err != nil {
		return passkeyCeremony{}, ErrPasskeyRejected
	}
	defer clear(plaintext)
	var ceremony passkeyCeremony
	if err := json.Unmarshal(plaintext, &ceremony); err != nil || ceremony.Purpose != purpose || time.Now().After(ceremony.Session.Expires) {
		return passkeyCeremony{}, ErrPasskeyRejected
	}
	return ceremony, nil
}

func (s *Service) loadPasskeyUser(ctx context.Context, userID string) (passkeyUser, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return passkeyUser{}, ErrPasskeyRejected
	}
	var name, status string
	var service bool
	err = s.db.QueryRowContext(ctx, `SELECT COALESCE(c.login_name, u.display_name), u.status, EXISTS (SELECT 1 FROM registry_service_accounts a WHERE a.user_id = u.user_id) FROM registry_users u LEFT JOIN registry_local_credentials c ON c.user_id = u.user_id WHERE u.user_id = `+bind(s.driver, 1), id.String()).Scan(&name, &status, &service)
	if err != nil || status != "active" || service {
		return passkeyUser{}, ErrPasskeyRejected
	}
	user := passkeyUser{id: id, name: name}
	rows, err := s.db.QueryContext(ctx, `SELECT credential FROM registry_webauthn_credentials WHERE user_id = `+bind(s.driver, 1), id.String())
	if err != nil {
		return passkeyUser{}, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return passkeyUser{}, ErrUnavailable
		}
		var credential webauthn.Credential
		if err := json.Unmarshal(raw, &credential); err != nil {
			return passkeyUser{}, ErrUnavailable
		}
		user.credentials = append(user.credentials, credential)
	}
	return user, rows.Err()
}

// BeginPasskeyRegistration starts adding a passkey to an authenticated
// account. The HTTP layer requires a recent second factor when the account
// already has one. Passkeys are discoverable and require user verification.
func (s *Service) BeginPasskeyRegistration(ctx context.Context, userID, name string) (json.RawMessage, string, error) {
	if !s.PasskeysEnabled() {
		return nil, "", ErrPasskeysDisabled
	}
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 100 || strings.ContainsAny(name, "\x00\r\n") {
		return nil, "", ErrPasskeyRejected
	}
	user, err := s.loadPasskeyUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	if len(user.credentials) >= maxPasskeysPerUser {
		return nil, "", ErrPasskeyLimit
	}
	exclusions := make([]protocol.CredentialDescriptor, 0, len(user.credentials))
	for _, credential := range user.credentials {
		exclusions = append(exclusions, credential.Descriptor())
	}
	options, session, err := s.passkeys.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(), UserVerification: protocol.VerificationRequired}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(exclusions),
	)
	if err != nil {
		return nil, "", ErrUnavailable
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		return nil, "", ErrUnavailable
	}
	sealed, err := s.sealCeremony(passkeyCeremony{Purpose: "register", UserID: user.id.String(), Name: name, Session: *session})
	return encoded, sealed, err
}

// FinishPasskeyRegistration verifies the authenticator's response and stores
// the credential. userID must be the account of the current session.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, userID, sealed string, request *http.Request) (Passkey, error) {
	if !s.PasskeysEnabled() {
		return Passkey{}, ErrPasskeysDisabled
	}
	ceremony, err := s.openCeremony(sealed, "register")
	if err != nil || ceremony.UserID != userID {
		return Passkey{}, ErrPasskeyRejected
	}
	user, err := s.loadPasskeyUser(ctx, userID)
	if err != nil {
		return Passkey{}, err
	}
	credential, err := s.passkeys.FinishRegistration(user, ceremony.Session, request)
	if err != nil || !credential.Flags.UserVerified {
		return Passkey{}, ErrPasskeyRejected
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		return Passkey{}, ErrUnavailable
	}
	id := base64.RawURLEncoding.EncodeToString(credential.ID)
	now := time.Now().UTC().Truncate(time.Millisecond)
	err = s.withTransaction(ctx, func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_webauthn_credentials WHERE user_id = `+bind(s.driver, 1), userID).Scan(&count); err != nil {
			return ErrUnavailable
		}
		if count >= maxPasskeysPerUser {
			return ErrPasskeyLimit
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO registry_webauthn_credentials (credential_id, user_id, name, credential, sign_count, created_at_ms) VALUES (`+bind(s.driver, 1)+`, `+bind(s.driver, 2)+`, `+bind(s.driver, 3)+`, `+bind(s.driver, 4)+`, `+bind(s.driver, 5)+`, `+bind(s.driver, 6)+`)`, id, userID, ceremony.Name, encoded, int64(credential.Authenticator.SignCount), now.UnixMilli()); err != nil {
			return ErrPasskeyRejected
		}
		return s.recordRecoveryAudit(ctx, tx, userID, "", "passkey.registered", userID)
	})
	if err != nil {
		return Passkey{}, err
	}
	return Passkey{ID: id, Name: ceremony.Name, CreatedAt: now}, nil
}

// BeginPasskeyLogin starts a passwordless sign-in.
func (s *Service) BeginPasskeyLogin(ctx context.Context) (json.RawMessage, string, error) {
	if !s.PasskeysEnabled() {
		return nil, "", ErrPasskeysDisabled
	}
	options, session, err := s.passkeys.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", ErrUnavailable
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		return nil, "", ErrUnavailable
	}
	sealed, err := s.sealCeremony(passkeyCeremony{Purpose: "login", Session: *session})
	return encoded, sealed, err
}

// FinishPasskeyLogin verifies an assertion with user verification and opens
// a fully authenticated session: the passkey proved possession and the
// authenticator verified the person, so it satisfies the MFA policy alone.
func (s *Service) FinishPasskeyLogin(ctx context.Context, sealed string, request *http.Request) (sessions.Credentials, error) {
	if !s.PasskeysEnabled() {
		return sessions.Credentials{}, ErrPasskeysDisabled
	}
	ceremony, err := s.openCeremony(sealed, "login")
	if err != nil {
		return sessions.Credentials{}, err
	}
	var resolved passkeyUser
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if len(userHandle) != 16 {
			return nil, ErrPasskeyRejected
		}
		id, err := uuid.FromBytes(userHandle)
		if err != nil {
			return nil, ErrPasskeyRejected
		}
		user, err := s.loadPasskeyUser(ctx, id.String())
		if err != nil {
			return nil, err
		}
		resolved = user
		return user, nil
	}
	credential, err := s.passkeys.FinishDiscoverableLogin(handler, ceremony.Session, request)
	if err != nil || credential == nil {
		return sessions.Credentials{}, ErrPasskeyRejected
	}
	// Many authenticators keep their counter at zero, so the counter cannot
	// stop a replay inside the ceremony's lifetime: each challenge is
	// accepted once.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM registry_trusted_publishing_tokens WHERE expires_at_ms < `+bind(s.driver, 1), time.Now().UTC().UnixMilli()); err != nil {
		return sessions.Credentials{}, ErrUnavailable
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO registry_trusted_publishing_tokens (token_id, provider, expires_at_ms) VALUES (`+bind(s.driver, 1)+`, 'webauthn', `+bind(s.driver, 2)+`)`, "webauthn:"+ceremony.Session.Challenge, ceremony.Session.Expires.UTC().UnixMilli()); err != nil {
		return sessions.Credentials{}, ErrPasskeyRejected
	}
	// A counter that did not advance may mean the credential was cloned.
	if credential.Authenticator.CloneWarning {
		return sessions.Credentials{}, ErrPasskeyRejected
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		return sessions.Credentials{}, ErrUnavailable
	}
	id := base64.RawURLEncoding.EncodeToString(credential.ID)
	result, err := s.db.ExecContext(ctx, `UPDATE registry_webauthn_credentials SET credential = `+bind(s.driver, 1)+`, sign_count = `+bind(s.driver, 2)+`, last_used_at_ms = `+bind(s.driver, 3)+` WHERE credential_id = `+bind(s.driver, 4)+` AND user_id = `+bind(s.driver, 5), encoded, int64(credential.Authenticator.SignCount), time.Now().UTC().UnixMilli(), id, resolved.id.String())
	if err != nil {
		return sessions.Credentials{}, ErrUnavailable
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return sessions.Credentials{}, ErrPasskeyRejected
	}
	credentials, err := s.sessions.CreateVerified(ctx, resolved.id.String())
	if err != nil {
		return sessions.Credentials{}, ErrUnavailable
	}
	return credentials, nil
}

func (s *Service) ListPasskeys(ctx context.Context, userID string) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT credential_id, name, created_at_ms, last_used_at_ms FROM registry_webauthn_credentials WHERE user_id = `+bind(s.driver, 1)+` ORDER BY created_at_ms`, userID)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var passkeys []Passkey
	for rows.Next() {
		var passkey Passkey
		var created int64
		var used sql.NullInt64
		if err := rows.Scan(&passkey.ID, &passkey.Name, &created, &used); err != nil {
			return nil, ErrUnavailable
		}
		passkey.CreatedAt = time.UnixMilli(created).UTC()
		if used.Valid {
			at := time.UnixMilli(used.Int64).UTC()
			passkey.LastUsedAt = &at
		}
		passkeys = append(passkeys, passkey)
	}
	return passkeys, rows.Err()
}

func (s *Service) DeletePasskey(ctx context.Context, userID, passkeyID string) error {
	return s.withTransaction(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM registry_webauthn_credentials WHERE user_id = `+bind(s.driver, 1)+` AND credential_id = `+bind(s.driver, 2), userID, passkeyID)
		if err != nil {
			return ErrUnavailable
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrPasskeyUnknown
		}
		return s.recordRecoveryAudit(ctx, tx, userID, "", "passkey.deleted", userID)
	})
}
