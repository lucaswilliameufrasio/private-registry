package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/auth"
)

const (
	muiraTestClientID     = "synthetic-registry-client"
	muiraTestClientSecret = "synthetic-client-secret-never-reuse"
	muiraTestRedirect     = authTestOrigin + "/api/v1/auth/muira/callback"
)

type muiraGrant struct {
	challenge string
	nonce     string
	subject   string
	audience  string
}

// fakeMuira is an in-process OIDC provider with Muira's contract: confidential
// client via client_secret_post, PKCE S256 and RS256 id_tokens.
type fakeMuira struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	grants map[string]muiraGrant
	tokens int
}

func newFakeMuira(t *testing.T) *fakeMuira {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeMuira{t: t, key: key, grants: make(map[string]muiraGrant)}
	fake.server = httptest.NewTLSServer(http.HandlerFunc(fake.serve))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeMuira) serve(w http.ResponseWriter, r *http.Request) {
	issuer := f.server.URL
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/oauth/jwks.json", "authorization_endpoint": issuer + "/oauth/authorize", "token_endpoint": issuer + "/oauth/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
	case "/oauth/jwks.json":
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "fixture", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes())}}})
	case "/oauth/token":
		if err := r.ParseForm(); err != nil || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.tokens++
		grant, ok := f.grants[r.PostForm.Get("code")]
		delete(f.grants, r.PostForm.Get("code"))
		f.mu.Unlock()
		digest := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		_, _, basic := r.BasicAuth()
		if !ok || basic || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("client_id") != muiraTestClientID || r.PostForm.Get("client_secret") != muiraTestClientSecret || r.PostForm.Get("redirect_uri") != muiraTestRedirect || base64.RawURLEncoding.EncodeToString(digest[:]) != grant.challenge {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-access", "token_type": "Bearer", "expires_in": 3600, "id_token": f.sign(grant)})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeMuira) sign(grant muiraGrant) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{"iss": f.server.URL, "aud": grant.audience, "sub": grant.subject, "nonce": grant.nonce, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "amr": []string{"pwd", "mfa"}, "email": "admin@example.invalid", "email_verified": true})
	if err != nil {
		f.t.Fatal(err)
	}
	body := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(body))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		f.t.Fatal(err)
	}
	return body + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// authorize plays the provider's consent step for the authorize URL the
// registry produced and returns the state and the one-time code.
func (f *fakeMuira) authorize(authorizeURL, subject string, mutate func(*muiraGrant)) (state, code string) {
	f.t.Helper()
	parsed, err := url.Parse(authorizeURL)
	if err != nil {
		f.t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != f.server.URL+"/oauth/authorize" || query.Get("response_type") != "code" || query.Get("client_id") != muiraTestClientID || query.Get("redirect_uri") != muiraTestRedirect || query.Get("code_challenge_method") != "S256" || len(query.Get("code_challenge")) != 43 || len(query.Get("state")) < 32 || len(query.Get("nonce")) < 32 || !strings.Contains(query.Get("scope"), "openid") {
		f.t.Fatalf("authorize request does not follow the Muira contract: %s", authorizeURL)
	}
	grant := muiraGrant{challenge: query.Get("code_challenge"), nonce: query.Get("nonce"), subject: subject, audience: muiraTestClientID}
	if mutate != nil {
		mutate(&grant)
	}
	code = uuid.NewString()
	f.mu.Lock()
	f.grants[code] = grant
	f.mu.Unlock()
	return query.Get("state"), code
}

func newMuiraHTTPFixture(t *testing.T) (authHTTPFixture, http.Handler, *fakeMuira) {
	t.Helper()
	fixture := newAuthHTTPFixture(t)
	fake := newFakeMuira(t)
	client := fake.server.Client()
	client.Timeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := fixture.service.EnableMuira(ctx, auth.MuiraOptions{Issuer: fake.server.URL, ClientID: muiraTestClientID, ClientSecret: muiraTestClientSecret, RedirectURL: muiraTestRedirect, HTTPClient: client}); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin})
	if err != nil {
		t.Fatal(err)
	}
	return fixture, handler, fake
}

func muiraSubject(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

func responseCookies(response *httptest.ResponseRecorder) map[string]*http.Cookie {
	cookies := make(map[string]*http.Cookie)
	for _, cookie := range response.Result().Cookies() {
		cookies[cookie.Name] = cookie
	}
	return cookies
}

func muiraStartLogin(t *testing.T, handler http.Handler) (string, map[string]*http.Cookie) {
	t.Helper()
	start := authHTTPRequest(handler, http.MethodGet, "/api/v1/auth/muira/start", "", "", "registry.example")
	if start.Code != http.StatusFound {
		t.Fatalf("Muira start: status=%d body=%s", start.Code, start.Body.String())
	}
	cookies := responseCookies(start)
	state := cookies[muiraStateCookieName]
	if state == nil || state.Value == "" || !state.HttpOnly || !state.Secure || state.Path != "/" || state.Domain != "" || state.SameSite != http.SameSiteLaxMode || state.MaxAge != 600 {
		t.Fatalf("Muira state cookie is not a short-lived host-only HttpOnly cookie: %+v", state)
	}
	return start.Header().Get("Location"), map[string]*http.Cookie{muiraStateCookieName: state}
}

func muiraCallback(handler http.Handler, state, code string, cookies map[string]*http.Cookie) *httptest.ResponseRecorder {
	return authHTTPRequestWithCookies(handler, http.MethodGet, "/api/v1/auth/muira/callback?state="+url.QueryEscape(state)+"&code="+url.QueryEscape(code), "", "", "registry.example", cookies, "")
}

func muiraAdminMFACookies(t *testing.T, handler http.Handler) map[string]*http.Cookie {
	t.Helper()
	login := authHTTPRequest(handler, http.MethodPost, "/api/v1/auth/login", fmt.Sprintf(`{"login_name":"%s","password":"%s"}`, authTestLogin, authTestPassword), authTestOrigin, "registry.example")
	if login.Code != http.StatusOK {
		t.Fatalf("local login failed: %d", login.Code)
	}
	cookies := assertSessionCookies(t, login)
	begin := authHTTPRequestWithCookies(handler, http.MethodPost, "/api/v1/auth/mfa/enrollment", "", authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value)
	var enrollment enrollmentResponse
	if err := json.Unmarshal(begin.Body.Bytes(), &enrollment); err != nil || begin.Code != http.StatusOK {
		t.Fatalf("enrollment start failed: %d %v", begin.Code, err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	complete := authHTTPRequestWithCookies(handler, http.MethodPost, "/api/v1/auth/mfa/enrollment/complete", fmt.Sprintf(`{"code":"%s"}`, authHTTPOTP(secret, time.Now().Unix()/30)), authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value)
	if complete.Code != http.StatusOK {
		t.Fatalf("enrollment completion failed: %d", complete.Code)
	}
	return assertSessionCookies(t, complete)
}

func TestMuiraRoutesAreAbsentUnlessEnabled(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	for _, path := range []string{"/api/v1/auth/muira/start", "/api/v1/auth/muira/callback?state=a&code=b"} {
		if response := authHTTPRequest(fixture.handler, http.MethodGet, path, "", "", "registry.example"); response.Code != http.StatusNotFound {
			t.Fatalf("%s exists without Muira: %d", path, response.Code)
		}
	}
	if _, err := fixture.service.BeginMuiraLogin(context.Background()); !errors.Is(err, auth.ErrMuiraDisabled) {
		t.Fatalf("disabled Muira started a login: %v", err)
	}
}

func TestMuiraLoginRequiresProvisionedSubjectAndBoundState(t *testing.T) {
	fixture, handler, fake := newMuiraHTTPFixture(t)
	subject := muiraSubject(t)

	// An authenticated Muira user that nobody provisioned gets no account.
	location, stateCookie := muiraStartLogin(t, handler)
	state, code := fake.authorize(location, subject, nil)
	unknown := muiraCallback(handler, state, code, stateCookie)
	if unknown.Code != http.StatusUnauthorized || responseCookies(unknown)[sessionCookieName] != nil {
		t.Fatalf("unprovisioned Muira subject was signed in: status=%d", unknown.Code)
	}
	if cleared := responseCookies(unknown)[muiraStateCookieName]; cleared == nil || cleared.MaxAge >= 0 {
		t.Fatal("callback did not clear the state cookie")
	}
	var users int
	if err := fixture.db.QueryRow(`SELECT COUNT(*) FROM registry_users`).Scan(&users); err != nil || users != 1 {
		t.Fatalf("callback created an account: users=%d err=%v", users, err)
	}

	admin := muiraAdminMFACookies(t, handler)
	body := fmt.Sprintf(`{"subject":"%s","display_name":"Synthetic Muira Member"}`, subject)
	if response := authHTTPRequestWithCookies(handler, http.MethodPost, "/api/v1/admin/muira/users", body, authTestOrigin, "registry.example", admin, ""); response.Code != http.StatusForbidden {
		t.Fatalf("provisioning without CSRF: %d", response.Code)
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPost, "/api/v1/admin/muira/users", `{"subject":"member@example.invalid","display_name":"By Email"}`, authTestOrigin, "registry.example", admin, admin[csrfCookieName].Value); response.Code != http.StatusBadRequest {
		t.Fatalf("provisioning by email was not rejected: %d", response.Code)
	}
	provisioned := authHTTPRequestWithCookies(handler, http.MethodPost, "/api/v1/admin/muira/users", body, authTestOrigin, "registry.example", admin, admin[csrfCookieName].Value)
	var created muiraProvisionResponse
	if err := json.Unmarshal(provisioned.Body.Bytes(), &created); err != nil || provisioned.Code != http.StatusCreated || created.UserID == "" {
		t.Fatalf("provisioning failed: status=%d body=%s", provisioned.Code, provisioned.Body.String())
	}
	if again := authHTTPRequestWithCookies(handler, http.MethodPost, "/api/v1/admin/muira/users", body, authTestOrigin, "registry.example", admin, admin[csrfCookieName].Value); again.Code != http.StatusConflict {
		t.Fatalf("duplicate subject provisioning: %d", again.Code)
	}
	if _, err := fixture.service.ProvisionMuiraUser(context.Background(), created.UserID, muiraSubject(t), "Escalation"); !errors.Is(err, auth.ErrMuiraForbidden) {
		t.Fatalf("non-administrator provisioned a user: %v", err)
	}

	for name, attempt := range map[string]func() *httptest.ResponseRecorder{
		"mismatched state": func() *httptest.ResponseRecorder {
			location, cookie := muiraStartLogin(t, handler)
			_, code := fake.authorize(location, subject, nil)
			return muiraCallback(handler, "attacker-chosen-state", code, cookie)
		},
		"missing state cookie": func() *httptest.ResponseRecorder {
			location, _ := muiraStartLogin(t, handler)
			state, code := fake.authorize(location, subject, nil)
			return muiraCallback(handler, state, code, nil)
		},
		"state cookie from another attempt": func() *httptest.ResponseRecorder {
			location, _ := muiraStartLogin(t, handler)
			_, other := muiraStartLogin(t, handler)
			state, code := fake.authorize(location, subject, nil)
			return muiraCallback(handler, state, code, other)
		},
		"tampered state cookie": func() *httptest.ResponseRecorder {
			location, cookie := muiraStartLogin(t, handler)
			state, code := fake.authorize(location, subject, nil)
			tampered := *cookie[muiraStateCookieName]
			tampered.Value = tampered.Value[:len(tampered.Value)-2] + "AA"
			return muiraCallback(handler, state, code, map[string]*http.Cookie{muiraStateCookieName: &tampered})
		},
		"wrong nonce": func() *httptest.ResponseRecorder {
			location, cookie := muiraStartLogin(t, handler)
			state, code := fake.authorize(location, subject, func(grant *muiraGrant) { grant.nonce = "replayed-nonce" })
			return muiraCallback(handler, state, code, cookie)
		},
		"token for another client": func() *httptest.ResponseRecorder {
			location, cookie := muiraStartLogin(t, handler)
			state, code := fake.authorize(location, subject, func(grant *muiraGrant) { grant.audience = "other-client" })
			return muiraCallback(handler, state, code, cookie)
		},
		"code bound to another verifier": func() *httptest.ResponseRecorder {
			location, cookie := muiraStartLogin(t, handler)
			state, code := fake.authorize(location, subject, func(grant *muiraGrant) { grant.challenge = strings.Repeat("A", 43) })
			return muiraCallback(handler, state, code, cookie)
		},
		"unknown code": func() *httptest.ResponseRecorder {
			location, cookie := muiraStartLogin(t, handler)
			state, _ := fake.authorize(location, subject, nil)
			return muiraCallback(handler, state, "never-issued", cookie)
		},
	} {
		response := attempt()
		if response.Code != http.StatusUnauthorized || responseCookies(response)[sessionCookieName] != nil {
			t.Errorf("%s: status=%d, session issued=%v", name, response.Code, responseCookies(response)[sessionCookieName] != nil)
		}
	}

	_, cookie := muiraStartLogin(t, handler)
	before := fake.tokens
	denied := authHTTPRequestWithCookies(handler, http.MethodGet, "/api/v1/auth/muira/callback?error=access_denied&error_description=%3Cscript%3E&state=x", "", "", "registry.example", cookie, "")
	if denied.Code != http.StatusUnauthorized || strings.Contains(denied.Body.String(), "script") || fake.tokens != before {
		t.Fatalf("provider error handling: status=%d body=%s", denied.Code, denied.Body.String())
	}
	location, cookie = muiraStartLogin(t, handler)
	state, code = fake.authorize(location, subject, nil)
	crossOrigin := authHTTPRequestWithCookies(handler, http.MethodGet, "/api/v1/auth/muira/callback?state="+state+"&code="+code, "", "https://attacker.example", "registry.example", cookie, "")
	if crossOrigin.Code != http.StatusForbidden {
		t.Fatalf("cross-origin callback fetch was accepted: %d", crossOrigin.Code)
	}

	location, cookie = muiraStartLogin(t, handler)
	state, code = fake.authorize(location, subject, nil)
	signedIn := muiraCallback(handler, state, code, cookie)
	var completion muiraCompletionResponse
	if err := json.Unmarshal(signedIn.Body.Bytes(), &completion); err != nil || signedIn.Code != http.StatusOK || completion.Stage != string(auth.StageAuthenticated) {
		t.Fatalf("provisioned Muira login failed: status=%d body=%s", signedIn.Code, signedIn.Body.String())
	}
	session := assertSessionCookies(t, signedIn)
	if strings.Contains(signedIn.Body.String(), session[sessionCookieName].Value) {
		t.Fatal("callback exposed the session bearer in the body")
	}
	if list := authHTTPRequestWithCookies(handler, http.MethodGet, "/api/v1/workspaces", "", "", "registry.example", session, ""); list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `[]`) {
		t.Fatalf("Muira session is unusable or received implicit access: status=%d body=%s", list.Code, list.Body.String())
	}
	if replay := muiraCallback(handler, state, code, cookie); replay.Code != http.StatusUnauthorized {
		t.Fatalf("authorization code replay was accepted: %d", replay.Code)
	}

	// A suspended account keeps its link but cannot sign in.
	if _, err := fixture.db.Exec(`UPDATE registry_users SET status = 'suspended' WHERE user_id = ?`, created.UserID); err != nil {
		t.Fatal(err)
	}
	location, cookie = muiraStartLogin(t, handler)
	state, code = fake.authorize(location, subject, nil)
	if suspended := muiraCallback(handler, state, code, cookie); suspended.Code != http.StatusUnauthorized {
		t.Fatalf("suspended account signed in through Muira: %d", suspended.Code)
	}
	if err := fixture.service.UnlinkMuira(context.Background(), created.UserID); !errors.Is(err, auth.ErrMuiraConflict) {
		t.Fatalf("passwordless account was allowed to drop its only sign-in method: %v", err)
	}
}

func TestMuiraLinkKeepsLocalMFAAuthoritative(t *testing.T) {
	fixture, handler, fake := newMuiraHTTPFixture(t)
	subject := muiraSubject(t)
	admin := muiraAdminMFACookies(t, handler)

	if response := authHTTPRequestWithCookies(handler, http.MethodPost, "/api/v1/auth/muira/link", "", authTestOrigin, "registry.example", nil, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous link start: %d", response.Code)
	}
	startLink := func() (string, map[string]*http.Cookie) {
		t.Helper()
		response := authHTTPRequestWithCookies(handler, http.MethodPost, "/api/v1/auth/muira/link", "", authTestOrigin, "registry.example", admin, admin[csrfCookieName].Value)
		var body muiraLinkStartResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusOK || body.AuthorizeURL == "" {
			t.Fatalf("link start failed: status=%d body=%s", response.Code, response.Body.String())
		}
		return body.AuthorizeURL, map[string]*http.Cookie{muiraStateCookieName: responseCookies(response)[muiraStateCookieName]}
	}

	// A link attempt finished without the session that started it links nothing.
	location, stateCookie := startLink()
	state, code := fake.authorize(location, subject, nil)
	if orphan := muiraCallback(handler, state, code, stateCookie); orphan.Code != http.StatusUnauthorized {
		t.Fatalf("link completed without a session: %d", orphan.Code)
	}

	location, stateCookie = startLink()
	state, code = fake.authorize(location, subject, nil)
	withSession := map[string]*http.Cookie{muiraStateCookieName: stateCookie[muiraStateCookieName], sessionCookieName: admin[sessionCookieName]}
	linked := muiraCallback(handler, state, code, withSession)
	if linked.Code != http.StatusOK || !strings.Contains(linked.Body.String(), `"linked"`) || responseCookies(linked)[sessionCookieName] != nil {
		t.Fatalf("link failed or replaced the session: status=%d body=%s", linked.Code, linked.Body.String())
	}
	var audited int
	if err := fixture.db.QueryRow(`SELECT COUNT(*) FROM registry_audit_events WHERE action = 'muira_identity.link'`).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("link was not audited: %d %v", audited, err)
	}

	location, stateCookie = startLink()
	state, code = fake.authorize(location, muiraSubject(t), nil)
	withSession[muiraStateCookieName] = stateCookie[muiraStateCookieName]
	if second := muiraCallback(handler, state, code, withSession); second.Code != http.StatusConflict {
		t.Fatalf("second Muira identity on one account: %d", second.Code)
	}

	// Muira replaces only the password step: the administrator still owes the
	// local second factor, whatever amr the provider reported.
	location, loginCookie := muiraStartLogin(t, handler)
	state, code = fake.authorize(location, subject, nil)
	signedIn := muiraCallback(handler, state, code, loginCookie)
	var completion muiraCompletionResponse
	if err := json.Unmarshal(signedIn.Body.Bytes(), &completion); err != nil || signedIn.Code != http.StatusOK || completion.Stage != string(auth.StageMFAChallenge) {
		t.Fatalf("administrator Muira login skipped the local MFA challenge: status=%d body=%s", signedIn.Code, signedIn.Body.String())
	}
	challenge := assertSessionCookies(t, signedIn)
	if list := authHTTPRequestWithCookies(handler, http.MethodGet, "/api/v1/workspaces", "", "", "registry.example", challenge, ""); list.Code != http.StatusForbidden {
		t.Fatalf("challenge-stage Muira session reached protected data: %d", list.Code)
	}

	if response := authHTTPRequestWithCookies(handler, http.MethodDelete, "/api/v1/auth/muira/link", "", authTestOrigin, "registry.example", admin, admin[csrfCookieName].Value); response.Code != http.StatusNoContent {
		t.Fatalf("unlink failed: %d", response.Code)
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodDelete, "/api/v1/auth/muira/link", "", authTestOrigin, "registry.example", admin, admin[csrfCookieName].Value); response.Code != http.StatusNotFound {
		t.Fatalf("repeated unlink: %d", response.Code)
	}
	location, loginCookie = muiraStartLogin(t, handler)
	state, code = fake.authorize(location, subject, nil)
	if after := muiraCallback(handler, state, code, loginCookie); after.Code != http.StatusUnauthorized {
		t.Fatalf("unlinked Muira identity still signs in: %d", after.Code)
	}
	// Local sign-in keeps working with Muira enabled.
	if local := authHTTPRequest(handler, http.MethodPost, "/api/v1/auth/login", fmt.Sprintf(`{"login_name":"%s","password":"%s"}`, authTestLogin, authTestPassword), authTestOrigin, "registry.example"); local.Code != http.StatusOK {
		t.Fatalf("local login broke with Muira enabled: %d", local.Code)
	}
}
