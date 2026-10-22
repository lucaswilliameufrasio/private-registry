//go:build linux

package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"private-registry/internal/auth"
	"private-registry/internal/bootstrap"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/secrets"
	"private-registry/internal/sessions"
)

const (
	authTestOrigin   = "https://registry.example"
	authTestLogin    = "http.admin"
	authTestPassword = "synthetic-auth-http-password-never-reuse"
)

type authHTTPFixture struct {
	handler http.Handler
	service *auth.Service
}

func newAuthHTTPFixture(t *testing.T) authHTTPFixture {
	t.Helper()
	return newAuthHTTPFixtureWithConfig(t, AuthHTTPConfig{CanonicalOrigin: authTestOrigin})
}

func newAuthHTTPFixtureWithProxies(t *testing.T, proxies []netip.Prefix) authHTTPFixture {
	t.Helper()
	return newAuthHTTPFixtureWithConfig(t, AuthHTTPConfig{
		CanonicalOrigin: authTestOrigin,
		TrustedProxies:  proxies,
	})
}

func newAuthHTTPFixtureWithConfig(t *testing.T, authConfig AuthHTTPConfig) authHTTPFixture {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	keyDir := filepath.Join(root, "keys")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "master.key")
	if err := secrets.InitializeMasterKey(keyPath, dataDir); err != nil {
		t.Fatal(err)
	}
	key, err := secrets.LoadMasterKeyFile(keyPath, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)

	dbConfig := config.Config{
		DataDir:              dataDir,
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          filepath.Join(dataDir, "registry.sqlite"),
		DatabaseMaxOpenConns: 4,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	db, err := database.Open(ctx, dbConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test SQLite database: %v", err)
		}
	})
	if _, err := migrations.Migrate(ctx, db, dbConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.CreateFirstAdmin(ctx, db, config.SQLite, bootstrap.AdminInput{
		LoginName:     authTestLogin,
		DisplayName:   "Synthetic Auth HTTP Administrator",
		Email:         "auth-http@example.invalid",
		Password:      []byte(authTestPassword),
		OperatorLabel: "synthetic-test-operator",
	}); err != nil {
		t.Fatal(err)
	}
	service, err := auth.New(db, config.SQLite, &key)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewHealth(db), service, authConfig)
	if err != nil {
		t.Fatal(err)
	}
	return authHTTPFixture{handler: handler, service: service}
}

func TestAuthHTTPCompletesEnrollmentChallengeAndLogout(t *testing.T) {
	fixture := newAuthHTTPFixture(t)

	login := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login",
		`{"login_name":"http.admin","password":"synthetic-auth-http-password-never-reuse"}`, authTestOrigin, "registry.example")
	if login.Code != http.StatusOK {
		t.Fatalf("login failed: status=%d body=%s", login.Code, login.Body.String())
	}
	var loginBody loginResponse
	if err := json.Unmarshal(login.Body.Bytes(), &loginBody); err != nil {
		t.Fatal(err)
	}
	if loginBody.Stage != string(auth.StageMFAEnrollment) {
		t.Fatalf("administrator did not enter the restricted enrollment stage: %+v", loginBody)
	}
	enrollmentCookies := assertSessionCookies(t, login)
	if strings.Contains(login.Body.String(), enrollmentCookies[sessionCookieName].Value) {
		t.Fatal("login response exposed the bearer token in JSON")
	}

	missingCSRF := authHTTPRequestWithCookies(fixture.handler, http.MethodPost,
		"/api/v1/auth/mfa/enrollment", "", authTestOrigin, "registry.example", enrollmentCookies, "")
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("enrollment accepted a request without the CSRF header: status=%d", missingCSRF.Code)
	}

	beginEnrollment := authHTTPRequestWithCookies(fixture.handler, http.MethodPost,
		"/api/v1/auth/mfa/enrollment", "", authTestOrigin, "registry.example", enrollmentCookies,
		enrollmentCookies[csrfCookieName].Value)
	if beginEnrollment.Code != http.StatusOK {
		t.Fatalf("MFA enrollment did not start: status=%d body=%s", beginEnrollment.Code, beginEnrollment.Body.String())
	}
	var enrollment enrollmentResponse
	if err := json.Unmarshal(beginEnrollment.Body.Bytes(), &enrollment); err != nil {
		t.Fatal(err)
	}
	if enrollment.Secret == "" || !strings.HasPrefix(enrollment.OTPAuthURL, "otpauth://totp/") || enrollment.ExpiresAt == "" {
		t.Fatalf("MFA enrollment response is incomplete: %+v", enrollment)
	}
	if strings.Contains(beginEnrollment.Body.String(), enrollmentCookies[sessionCookieName].Value) {
		t.Fatal("MFA enrollment response exposed the bearer token")
	}

	wrongOrigin := authHTTPRequestWithCookies(fixture.handler, http.MethodPost,
		"/api/v1/auth/mfa/enrollment/complete", `{"code":"000000"}`, "https://attacker.example",
		"registry.example", enrollmentCookies, enrollmentCookies[csrfCookieName].Value)
	if wrongOrigin.Code != http.StatusForbidden {
		t.Fatalf("MFA confirmation accepted a non-canonical Origin: status=%d", wrongOrigin.Code)
	}

	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	code := authHTTPOTP(secret, time.Now().Unix()/30)
	completeEnrollment := authHTTPRequestWithCookies(fixture.handler, http.MethodPost,
		"/api/v1/auth/mfa/enrollment/complete", fmt.Sprintf(`{"code":"%s"}`, code), authTestOrigin,
		"registry.example", enrollmentCookies, enrollmentCookies[csrfCookieName].Value)
	if completeEnrollment.Code != http.StatusOK {
		t.Fatalf("MFA enrollment confirmation failed: status=%d body=%s", completeEnrollment.Code, completeEnrollment.Body.String())
	}
	var completion enrollmentCompletionResponse
	if err := json.Unmarshal(completeEnrollment.Body.Bytes(), &completion); err != nil {
		t.Fatal(err)
	}
	if completion.Stage != string(auth.StageAuthenticated) || len(completion.RecoveryCodes) != 10 {
		t.Fatalf("MFA enrollment did not complete with one-time recovery codes: stage=%q code_count=%d",
			completion.Stage, len(completion.RecoveryCodes))
	}
	mfaCookies := assertSessionCookies(t, completeEnrollment)
	if mfaCookies[sessionCookieName].Value == enrollmentCookies[sessionCookieName].Value {
		t.Fatal("MFA enrollment did not rotate the restricted bearer")
	}
	if _, err := fixture.service.ValidateWithCSRF(context.Background(), enrollmentCookies[sessionCookieName].Value,
		enrollmentCookies[csrfCookieName].Value); !errors.Is(err, sessions.ErrSessionUnavailable) {
		t.Fatalf("restricted session remained valid after MFA elevation: %v", err)
	}

	challenge := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login",
		`{"login_name":"http.admin","password":"synthetic-auth-http-password-never-reuse"}`, authTestOrigin, "registry.example")
	if challenge.Code != http.StatusOK {
		t.Fatalf("second login failed: status=%d body=%s", challenge.Code, challenge.Body.String())
	}
	var challengeBody loginResponse
	if err := json.Unmarshal(challenge.Body.Bytes(), &challengeBody); err != nil {
		t.Fatal(err)
	}
	if challengeBody.Stage != string(auth.StageMFAChallenge) {
		t.Fatalf("enrolled administrator skipped the MFA challenge: %+v", challengeBody)
	}
	challengeCookies := assertSessionCookies(t, challenge)
	completeChallenge := authHTTPRequestWithCookies(fixture.handler, http.MethodPost,
		"/api/v1/auth/mfa/challenge", fmt.Sprintf(`{"code":%q}`, completion.RecoveryCodes[0]),
		authTestOrigin, "registry.example", challengeCookies, challengeCookies[csrfCookieName].Value)
	if completeChallenge.Code != http.StatusOK {
		t.Fatalf("MFA challenge failed: status=%d body=%s", completeChallenge.Code, completeChallenge.Body.String())
	}
	var completedChallenge loginResponse
	if err := json.Unmarshal(completeChallenge.Body.Bytes(), &completedChallenge); err != nil {
		t.Fatal(err)
	}
	if completedChallenge.Stage != string(auth.StageAuthenticated) {
		t.Fatalf("MFA challenge returned an unexpected stage: %+v", completedChallenge)
	}
	activeCookies := assertSessionCookies(t, completeChallenge)
	if activeCookies[sessionCookieName].Value == challengeCookies[sessionCookieName].Value {
		t.Fatal("MFA challenge did not rotate the restricted bearer")
	}

	logout := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, "/api/v1/auth/logout", "",
		authTestOrigin, "registry.example", activeCookies, activeCookies[csrfCookieName].Value)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout failed: status=%d body=%s", logout.Code, logout.Body.String())
	}
	assertClearedSessionCookies(t, logout)
	if _, err := fixture.service.ValidateWithCSRF(context.Background(), activeCookies[sessionCookieName].Value,
		activeCookies[csrfCookieName].Value); !errors.Is(err, sessions.ErrSessionUnavailable) {
		t.Fatalf("logged-out session remained valid: %v", err)
	}
}

func TestAuthHTTPRejectsWrongOriginsAndKeepsProtectedRoutesUnavailable(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	for _, test := range []struct {
		name   string
		origin string
		host   string
	}{
		{name: "missing origin", origin: "", host: "registry.example"},
		{name: "foreign origin", origin: "https://attacker.example", host: "registry.example"},
		{name: "host alias", origin: authTestOrigin, host: "alias.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login",
				`{"login_name":"http.admin","password":"synthetic-auth-http-password-never-reuse"}`,
				test.origin, test.host)
			if request.Code != http.StatusForbidden {
				t.Fatalf("request bypassed canonical origin validation: status=%d", request.Code)
			}
		})
	}
	for _, path := range []string{"/api/v1/workspaces", "/api/v1/admin", "/packages/private"} {
		request := httptest.NewRequest(http.MethodGet, "https://registry.example"+path, nil)
		request.Host = "registry.example"
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("unimplemented protected route %q became reachable: status=%d", path, response.Code)
		}
	}
}

func TestAuthHTTPRejectsMalformedOrAmbiguousJSON(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	for _, test := range []struct {
		name        string
		body        string
		contentType string
		wantStatus  int
	}{
		{name: "null object", body: "null", contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "duplicate password", body: `{"login_name":"http.admin","password":"first","password":"second"}`,
			contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "unknown field", body: `{"login_name":"http.admin","password":"x","extra":true}`,
			contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "multiple values", body: `{"login_name":"http.admin","password":"x"}{}`,
			contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "missing content type", body: `{"login_name":"http.admin","password":"x"}`,
			wantStatus: http.StatusUnsupportedMediaType},
		{name: "oversized body", body: strings.Repeat("x", maxAuthRequestBytes+1),
			contentType: "application/json", wantStatus: http.StatusRequestEntityTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost,
				"https://registry.example/api/v1/auth/login", strings.NewReader(test.body))
			request.Host = "registry.example"
			request.TLS = &tls.ConnectionState{}
			request.RemoteAddr = "192.0.2.10:54321"
			request.Header.Set("Origin", authTestOrigin)
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("unexpected status for malformed request: got=%d want=%d body=%s",
					response.Code, test.wantStatus, response.Body.String())
			}
		})
	}
}

func TestAuthHTTPRequiresTLSOrTrustedTLSProxy(t *testing.T) {
	trustedProxy := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	fixture := newAuthHTTPFixtureWithProxies(t, trustedProxy)
	makeRequest := func(peerAddress, forwardedProtocol string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost,
			"https://registry.example/api/v1/auth/login",
			strings.NewReader(`{"login_name":"unknown.user","password":"synthetic-wrong-password"}`))
		request.Host = "registry.example"
		request.TLS = nil
		request.RemoteAddr = peerAddress
		request.Header.Set("Origin", authTestOrigin)
		request.Header.Set("Content-Type", "application/json")
		if forwardedProtocol != "" {
			request.Header.Set("X-Forwarded-Proto", forwardedProtocol)
		}
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		return response
	}

	if response := makeRequest("10.0.0.2:443", "https"); response.Code != http.StatusUnauthorized {
		t.Fatalf("trusted TLS proxy request was rejected before authentication: status=%d body=%s",
			response.Code, response.Body.String())
	}
	if response := makeRequest("10.0.0.2:443", "http"); response.Code != http.StatusForbidden {
		t.Fatalf("trusted proxy HTTP request was accepted: status=%d", response.Code)
	}
	if response := makeRequest("192.0.2.2:443", "https"); response.Code != http.StatusForbidden {
		t.Fatalf("untrusted peer spoofed an HTTPS proxy header: status=%d", response.Code)
	}
	if response := makeRequest("10.0.0.2:443", "https, http"); response.Code != http.StatusForbidden {
		t.Fatalf("ambiguous forwarded protocol was accepted: status=%d", response.Code)
	}
}

func TestClientAddressTrustsForwardingOnlyFromConfiguredPeers(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	request := httptest.NewRequest(http.MethodPost, "https://registry.example", nil)
	request.RemoteAddr = "10.0.0.2:443"
	request.Header.Set("X-Forwarded-For", "192.0.2.9, 10.0.0.1")
	address, err := clientAddress(request, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if address != "192.0.2.9" {
		t.Fatalf("trusted proxy chain resolved to the wrong client: %q", address)
	}

	request.RemoteAddr = "198.51.100.3:54321"
	request.Header.Set("X-Forwarded-For", "192.0.2.9")
	address, err = clientAddress(request, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if address != "198.51.100.3" {
		t.Fatalf("untrusted peer controlled the rate-limit address: %q", address)
	}

	request.RemoteAddr = "10.0.0.2:443"
	request.Header.Set("X-Forwarded-For", "not-an-address")
	if _, err := clientAddress(request, trusted); err == nil {
		t.Fatal("malformed forwarding chain from a trusted proxy was accepted")
	}
	request.Header.Set("X-Forwarded-For", strings.Repeat("1", maxForwardedForHeaderBytes+1))
	if _, err := clientAddress(request, trusted); err == nil {
		t.Fatal("oversized forwarding chain from a trusted proxy was accepted")
	}
}

func TestNormalizeOriginRequiresAWellFormedHTTPSOrigin(t *testing.T) {
	for _, value := range []string{
		"",
		"http://registry.example",
		"https://registry.example/",
		"https://registry.example/path",
		"https://registry.example?",
		"https://registry.example#",
		"https://user@registry.example",
		"https://registry.example:70000",
		"https://registry_example",
	} {
		if _, err := normalizeOrigin(value); err == nil {
			t.Errorf("invalid origin %q was accepted", value)
		}
	}
	for _, test := range []struct {
		value string
		want  string
	}{
		{value: "https://REGISTRY.example", want: "https://registry.example"},
		{value: "https://registry.example:443", want: "https://registry.example"},
		{value: "https://registry.example:8443", want: "https://registry.example:8443"},
		{value: "https://[2001:db8::1]", want: "https://[2001:db8::1]"},
	} {
		got, err := normalizeOrigin(test.value)
		if err != nil || got != test.want {
			t.Errorf("normalizeOrigin(%q) = %q, %v; want %q", test.value, got, err, test.want)
		}
	}
}

func authHTTPRequest(
	handler http.Handler,
	method, path, body, origin, host string,
) *httptest.ResponseRecorder {
	return authHTTPRequestWithCookies(handler, method, path, body, origin, host, nil, "")
}

func authHTTPRequestWithCookies(
	handler http.Handler,
	method, path, body, origin, host string,
	cookies map[string]*http.Cookie,
	csrfHeader string,
) *httptest.ResponseRecorder {
	var requestBody *strings.Reader
	if body != "" {
		requestBody = strings.NewReader(body)
	}
	var request *http.Request
	if requestBody == nil {
		request = httptest.NewRequest(method, "https://registry.example"+path, nil)
	} else {
		request = httptest.NewRequest(method, "https://registry.example"+path, requestBody)
		request.Header.Set("Content-Type", "application/json")
	}
	request.Host = host
	request.TLS = &tls.ConnectionState{}
	request.RemoteAddr = "192.0.2.10:54321"
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	if csrfHeader != "" {
		request.Header.Set(csrfHeaderName, csrfHeader)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertSessionCookies(t *testing.T, response *httptest.ResponseRecorder) map[string]*http.Cookie {
	t.Helper()
	cookies := make(map[string]*http.Cookie)
	for _, cookie := range response.Result().Cookies() {
		cookies[cookie.Name] = cookie
	}
	for _, name := range []string{sessionCookieName, csrfCookieName} {
		if cookies[name] == nil || cookies[name].Value == "" {
			t.Fatalf("response did not set %q cookie", name)
		}
		cookie := cookies[name]
		if cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatalf("cookie %q does not have host-only secure attributes: %+v", name, cookie)
		}
	}
	if !cookies[sessionCookieName].HttpOnly {
		t.Fatal("session bearer cookie is readable by JavaScript")
	}
	if cookies[csrfCookieName].HttpOnly {
		t.Fatal("CSRF cookie is not readable by the same-origin client")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("auth response may be cached: Cache-Control=%q", response.Header().Get("Cache-Control"))
	}
	return cookies
}

func assertClearedSessionCookies(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if (cookie.Name == sessionCookieName || cookie.Name == csrfCookieName) && cookie.MaxAge != -1 {
			t.Errorf("logout did not expire cookie %q: %+v", cookie.Name, cookie)
		}
	}
}

func authHTTPOTP(secret []byte, step int64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	index := digest[len(digest)-1] & 0x0f
	code := (uint32(digest[index])&0x7f)<<24 |
		(uint32(digest[index+1])&0xff)<<16 |
		(uint32(digest[index+2])&0xff)<<8 |
		(uint32(digest[index+3]) & 0xff)
	return fmt.Sprintf("%06d", code%1_000_000)
}
