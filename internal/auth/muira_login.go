package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"private-registry/internal/sessions"
)

const (
	muiraStateLifetime   = 10 * time.Minute
	muiraExchangeTimeout = 20 * time.Second
	muiraStateContext    = "private-registry/muira-authorization-state/v1"
	maxMuiraStateBytes   = 2048
	maxMuiraCodeBytes    = 2048
)

var (
	// ErrMuiraDisabled means the optional Muira sign-in is not configured.
	ErrMuiraDisabled = errors.New("Muira sign-in is not enabled")
	// ErrMuiraConflict means the Muira identity or the account is already linked.
	ErrMuiraConflict = errors.New("Muira identity or account is already linked")
	// ErrMuiraInvalid means caller-supplied link or provisioning data is malformed.
	ErrMuiraInvalid = errors.New("Muira identity data is invalid")
	// ErrMuiraForbidden means the actor may not manage Muira identities.
	ErrMuiraForbidden = errors.New("Muira identity management is not permitted")
)

// MuiraIntent distinguishes signing in from linking an already authenticated
// local account. The intent is sealed into the state and cannot be switched by
// the browser between start and callback.
type MuiraIntent string

const (
	MuiraIntentLogin MuiraIntent = "login"
	MuiraIntentLink  MuiraIntent = "link"
)

// MuiraOptions configures the optional provider. The HTTP client must already
// enforce the outbound network policy; the client secret is held in memory only.
type MuiraOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	HTTPClient   *http.Client
}

// MuiraStart is returned once per authorization attempt. SealedState must be
// stored in an HttpOnly cookie and presented again at the callback.
type MuiraStart struct {
	AuthorizeURL string
	SealedState  string
	ExpiresIn    time.Duration
}

type MuiraCompletion struct {
	Intent MuiraIntent
	// Result is set for the login intent only.
	Result Result
}

type muiraLogin struct {
	verifier *muiraVerifier
	oauth    oauth2.Config
	client   *http.Client
	issuer   string
}

type muiraState struct {
	State    string      `json:"s"`
	Nonce    string      `json:"n"`
	Verifier string      `json:"v"`
	Intent   MuiraIntent `json:"i"`
	UserID   string      `json:"u,omitempty"`
	Expires  int64       `json:"e"`
}

// EnableMuira performs discovery once and makes the Muira routes usable. Local
// authentication is unaffected. It must be called before serving requests.
func (s *Service) EnableMuira(ctx context.Context, options MuiraOptions) error {
	if err := s.validate(ctx); err != nil {
		return err
	}
	if s.key == nil || s.muira != nil || options.ClientSecret == "" || len(options.ClientSecret) > 4096 || options.HTTPClient == nil {
		return errors.New("Muira configuration is invalid")
	}
	redirect, err := parseRedirectURL(options.RedirectURL)
	if err != nil {
		return err
	}
	verifier, err := newMuiraVerifier(ctx, options.Issuer, options.ClientID, options.HTTPClient)
	if err != nil {
		return err
	}
	endpoint := verifier.endpoint
	// Muira accepts client_secret_post or client_secret_basic, never both.
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	s.muira = &muiraLogin{
		verifier: verifier,
		oauth:    oauth2.Config{ClientID: options.ClientID, ClientSecret: options.ClientSecret, Endpoint: endpoint, RedirectURL: redirect, Scopes: []string{"openid"}},
		client:   options.HTTPClient,
		issuer:   options.Issuer,
	}
	return nil
}

func parseRedirectURL(raw string) (string, error) {
	if raw == "" || len(raw) > 2048 || !strings.HasPrefix(raw, "https://") || strings.ContainsAny(raw, "?#\\ \t\r\n") {
		return "", errors.New("Muira redirect URL must be an absolute HTTPS URL without query or fragment")
	}
	return raw, nil
}

func (s *Service) MuiraEnabled() bool {
	return s != nil && s.muira != nil
}

// BeginMuiraLogin starts an anonymous sign-in attempt.
func (s *Service) BeginMuiraLogin(ctx context.Context) (MuiraStart, error) {
	return s.beginMuira(ctx, MuiraIntentLogin, "")
}

// BeginMuiraLink starts linking for an account the caller has already
// authenticated (the HTTP boundary requires a recent local MFA).
func (s *Service) BeginMuiraLink(ctx context.Context, userID string) (MuiraStart, error) {
	parsed, err := uuid.Parse(userID)
	if err != nil || parsed == uuid.Nil || parsed.String() != userID {
		return MuiraStart{}, ErrMuiraInvalid
	}
	return s.beginMuira(ctx, MuiraIntentLink, userID)
}

func (s *Service) beginMuira(ctx context.Context, intent MuiraIntent, userID string) (MuiraStart, error) {
	if err := s.validate(ctx); err != nil {
		return MuiraStart{}, err
	}
	if s.muira == nil {
		return MuiraStart{}, ErrMuiraDisabled
	}
	state, err := randomURLToken()
	if err != nil {
		return MuiraStart{}, ErrUnavailable
	}
	nonce, err := randomURLToken()
	if err != nil {
		return MuiraStart{}, ErrUnavailable
	}
	verifier := oauth2.GenerateVerifier()
	plaintext, err := json.Marshal(muiraState{State: state, Nonce: nonce, Verifier: verifier, Intent: intent, UserID: userID, Expires: time.Now().Add(muiraStateLifetime).Unix()})
	if err != nil {
		return MuiraStart{}, ErrUnavailable
	}
	defer clear(plaintext)
	sealed, err := s.key.Seal(plaintext, []byte(muiraStateContext))
	if err != nil {
		return MuiraStart{}, ErrUnavailable
	}
	authorizeURL := s.muira.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce))
	return MuiraStart{AuthorizeURL: authorizeURL, SealedState: base64.RawURLEncoding.EncodeToString(sealed), ExpiresIn: muiraStateLifetime}, nil
}

// CompleteMuira consumes one callback. sealedState comes from the cookie set
// at start; state and code come from the query string. bearerToken is the
// caller's current session and is only used by the link intent.
//
// A login only succeeds for a Muira subject that was explicitly linked or
// provisioned beforehand: no account is created and no grant is derived from
// token claims.
func (s *Service) CompleteMuira(ctx context.Context, sealedState, state, code, bearerToken string) (MuiraCompletion, error) {
	if err := s.validate(ctx); err != nil {
		return MuiraCompletion{}, err
	}
	if s.muira == nil {
		return MuiraCompletion{}, ErrMuiraDisabled
	}
	if sealedState == "" || len(sealedState) > maxMuiraStateBytes || state == "" || len(state) > 512 || code == "" || len(code) > maxMuiraCodeBytes {
		return MuiraCompletion{}, ErrRejected
	}
	envelope, err := base64.RawURLEncoding.DecodeString(sealedState)
	if err != nil {
		return MuiraCompletion{}, ErrRejected
	}
	plaintext, err := s.key.Open(envelope, []byte(muiraStateContext))
	if err != nil {
		return MuiraCompletion{}, ErrRejected
	}
	defer clear(plaintext)
	var attempt muiraState
	if err := json.Unmarshal(plaintext, &attempt); err != nil {
		return MuiraCompletion{}, ErrRejected
	}
	if time.Now().Unix() >= attempt.Expires || subtle.ConstantTimeCompare([]byte(attempt.State), []byte(state)) != 1 {
		return MuiraCompletion{}, ErrRejected
	}
	if attempt.Intent != MuiraIntentLogin && attempt.Intent != MuiraIntentLink {
		return MuiraCompletion{}, ErrRejected
	}

	exchangeCtx, cancel := context.WithTimeout(ctx, muiraExchangeTimeout)
	defer cancel()
	token, err := s.muira.oauth.Exchange(context.WithValue(exchangeCtx, oauth2.HTTPClient, s.muira.client), code, oauth2.VerifierOption(attempt.Verifier))
	if err != nil {
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) && retrieveErr.Response != nil && retrieveErr.Response.StatusCode >= 400 && retrieveErr.Response.StatusCode < 500 {
			return MuiraCompletion{}, ErrRejected
		}
		return MuiraCompletion{}, ErrUnavailable
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return MuiraCompletion{}, ErrRejected
	}
	subject, err := s.muira.verifier.verify(exchangeCtx, rawIDToken, attempt.Nonce)
	if err != nil {
		return MuiraCompletion{}, ErrRejected
	}

	if attempt.Intent == MuiraIntentLink {
		session, err := s.sessions.Validate(ctx, bearerToken)
		if err != nil {
			if errors.Is(err, sessions.ErrSessionUnavailable) {
				return MuiraCompletion{}, ErrRejected
			}
			return MuiraCompletion{}, ErrUnavailable
		}
		// The session that finishes the link must be the fully authenticated
		// account that started it.
		if session.Level != sessions.LevelMFA || session.UserID != attempt.UserID {
			return MuiraCompletion{}, ErrRejected
		}
		if err := s.linkMuiraIdentity(ctx, session.UserID, session.UserID, subject); err != nil {
			return MuiraCompletion{}, err
		}
		return MuiraCompletion{Intent: MuiraIntentLink}, nil
	}

	userID, err := s.resolveMuiraIdentity(ctx, s.muira.issuer, subject)
	if err != nil {
		return MuiraCompletion{}, err
	}
	requiresMFA, err := s.accountRequiresMFA(ctx, userID)
	if err != nil {
		return MuiraCompletion{}, ErrUnavailable
	}
	result, err := s.issuePrimarySession(ctx, userID, requiresMFA)
	if err != nil {
		return MuiraCompletion{}, err
	}
	return MuiraCompletion{Intent: MuiraIntentLogin, Result: result}, nil
}

// UnlinkMuira removes the caller's own link. An account without a local
// password keeps its link, otherwise it could never sign in again.
func (s *Service) UnlinkMuira(ctx context.Context, userID string) (retErr error) {
	if err := s.validate(ctx); err != nil {
		return err
	}
	if s.muira == nil {
		return ErrMuiraDisabled
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		if retErr != nil {
			_ = tx.Rollback()
		}
	}()
	var hasPassword bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_local_credentials WHERE user_id = `+bind(s.driver, 1)+`)`, userID).Scan(&hasPassword); err != nil {
		return ErrUnavailable
	}
	if !hasPassword {
		return ErrMuiraConflict
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM registry_external_identities WHERE provider_id = 'muira' AND user_id = `+bind(s.driver, 1)+` AND issuer = `+bind(s.driver, 2), userID, s.muira.issuer)
	if err != nil {
		return ErrUnavailable
	}
	if removed, err := result.RowsAffected(); err != nil {
		return ErrUnavailable
	} else if removed == 0 {
		return ErrRejected
	}
	if err := s.auditMuira(ctx, tx, userID, "muira_identity.unlink", userID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}

// ProvisionMuiraUser lets an instance administrator pre-authorize one Muira
// subject. The account has no local password and no grants; workspace
// membership and repository grants are still assigned explicitly. The subject
// is the Muira user UUID, never an email address.
func (s *Service) ProvisionMuiraUser(ctx context.Context, actorUserID, subject, displayName string) (_ string, retErr error) {
	if err := s.validate(ctx); err != nil {
		return "", err
	}
	if s.muira == nil {
		return "", ErrMuiraDisabled
	}
	displayName = strings.TrimSpace(displayName)
	if !validMuiraSubject(subject) || displayName == "" || !utf8.ValidString(displayName) || utf8.RuneCountInString(displayName) > 200 || strings.ContainsAny(displayName, "\x00\r\n") {
		return "", ErrMuiraInvalid
	}
	userID, err := uuid.NewV7()
	if err != nil {
		return "", ErrUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", ErrUnavailable
	}
	defer func() {
		if retErr != nil {
			_ = tx.Rollback()
		}
	}()
	var isAdmin bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_instance_admins AS admins JOIN registry_users AS users ON users.user_id = admins.user_id WHERE admins.user_id = `+bind(s.driver, 1)+` AND users.status = 'active')`, actorUserID).Scan(&isAdmin); err != nil {
		return "", ErrUnavailable
	}
	if !isAdmin {
		return "", ErrMuiraForbidden
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (`+bind(s.driver, 1)+`, `+bind(s.driver, 2)+`, `+bind(s.driver, 3)+`, `+bind(s.driver, 4)+`)`, userID.String(), displayName, now, now); err != nil {
		return "", ErrUnavailable
	}
	if err := s.insertMuiraIdentity(ctx, tx, userID.String(), subject, now); err != nil {
		return "", err
	}
	if err := s.auditMuira(ctx, tx, actorUserID, "muira_identity.provision", userID.String()); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", ErrUnavailable
	}
	return userID.String(), nil
}

func (s *Service) linkMuiraIdentity(ctx context.Context, actorUserID, userID, subject string) (retErr error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		if retErr != nil {
			_ = tx.Rollback()
		}
	}()
	if err := s.insertMuiraIdentity(ctx, tx, userID, subject, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if err := s.auditMuira(ctx, tx, actorUserID, "muira_identity.link", userID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}

// insertMuiraIdentity enforces one Muira identity per account and one account
// per Muira subject for the configured issuer.
func (s *Service) insertMuiraIdentity(ctx context.Context, tx *sql.Tx, userID, subject, now string) error {
	if !validMuiraSubject(subject) {
		return ErrMuiraInvalid
	}
	var taken bool
	query := `SELECT EXISTS (SELECT 1 FROM registry_external_identities WHERE provider_id = 'muira' AND issuer = ` + bind(s.driver, 1) + ` AND (subject = ` + bind(s.driver, 2) + ` OR user_id = ` + bind(s.driver, 3) + `))`
	if err := tx.QueryRowContext(ctx, query, s.muira.issuer, subject, userID).Scan(&taken); err != nil {
		return ErrUnavailable
	}
	if taken {
		return ErrMuiraConflict
	}
	identityID, err := uuid.NewV7()
	if err != nil {
		return ErrUnavailable
	}
	insert := `INSERT INTO registry_external_identities (external_identity_id, user_id, provider_id, issuer, subject, created_at) VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, 'muira', ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `)`
	if _, err := tx.ExecContext(ctx, insert, identityID.String(), userID, s.muira.issuer, subject, now); err != nil {
		// A concurrent link of the same subject loses on the unique index.
		return ErrMuiraConflict
	}
	return nil
}

func (s *Service) auditMuira(ctx context.Context, tx *sql.Tx, actorUserID, action, targetUserID string) error {
	eventID, err := uuid.NewV7()
	if err != nil {
		return ErrUnavailable
	}
	query := `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, actor_label, action, target_type, target_id, outcome, occurred_at) VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, 'user', NULL, ` + bind(s.driver, 3) + `, 'user', ` + bind(s.driver, 4) + `, 'succeeded', ` + bind(s.driver, 5) + `)`
	if _, err := tx.ExecContext(ctx, query, eventID.String(), actorUserID, action, targetUserID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return ErrUnavailable
	}
	return nil
}

// accountRequiresMFA mirrors the local-login rule: instance administrators and
// active workspace owners/administrators must hold a local second factor.
func (s *Service) accountRequiresMFA(ctx context.Context, userID string) (bool, error) {
	query := `SELECT (EXISTS (
			SELECT 1 FROM registry_instance_admins AS admins WHERE admins.user_id = ` + bind(s.driver, 1) + `
		) OR EXISTS (
			SELECT 1 FROM registry_workspace_memberships AS memberships
			JOIN registry_workspaces AS workspaces ON workspaces.workspace_id = memberships.workspace_id
			WHERE memberships.user_id = ` + bind(s.driver, 2) + `
				AND memberships.role IN ('owner', 'administrator')
				AND memberships.status = 'active'
				AND workspaces.status = 'active'
		))`
	var required bool
	if err := s.db.QueryRowContext(ctx, query, userID, userID).Scan(&required); err != nil {
		return false, err
	}
	return required, nil
}

func validMuiraSubject(subject string) bool {
	id, err := uuid.Parse(subject)
	return err == nil && id != uuid.Nil && id.Version() == 7 && id.String() == subject
}

func randomURLToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
