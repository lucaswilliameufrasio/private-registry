package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAccountRecovery(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx := context.Background()
	admin := muiraAdminMFACookies(t, fixture.handler)
	call := func(cookies map[string]*http.Cookie, method, path, body string) *httptest.ResponseRecorder {
		csrf := ""
		if cookies[csrfCookieName] != nil {
			csrf = cookies[csrfCookieName].Value
		}
		return authHTTPRequestWithCookies(fixture.handler, method, path, body, authTestOrigin, "registry.example", cookies, csrf)
	}
	login := func(name, password string) *httptest.ResponseRecorder {
		return authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login", fmt.Sprintf(`{"login_name":%q,"password":%q}`, name, password), authTestOrigin, "registry.example")
	}
	issue := func(cookies map[string]*http.Cookie, user string, resetMFA bool) (*httptest.ResponseRecorder, string) {
		response := call(cookies, http.MethodPost, "/api/v1/admin/users/"+user+"/recovery", fmt.Sprintf(`{"reset_mfa":%t}`, resetMFA))
		var body struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &body)
		return response, body.Token
	}
	complete := func(token, password string) *httptest.ResponseRecorder {
		return authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/recovery", fmt.Sprintf(`{"token":%q,"password":%q}`, token, password), authTestOrigin, "registry.example")
	}
	var adminID string
	if err := fixture.db.QueryRow(`SELECT user_id FROM registry_instance_admins`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	if response, _ := issue(admin, adminID, true); response.Code != http.StatusConflict {
		t.Fatalf("administrator recovered their own account: %d", response.Code)
	}

	member := seedHTTPUser(t, fixture, "forgetful.member")
	memberSession := assertSessionCookies(t, login("forgetful.member", "synthetic-http-member-password"))
	if response, _ := issue(memberSession, adminID, true); response.Code != http.StatusForbidden && response.Code != http.StatusUnauthorized {
		t.Fatalf("non-administrator issued a recovery: %d", response.Code)
	}
	// Second factors on file, to be removed by an MFA reset.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := fixture.db.Exec(`INSERT INTO registry_totp_credentials (user_id, secret_envelope, status, enrollment_expires_at, created_at, updated_at) VALUES (?, zeroblob(61), 'pending', ?, ?, ?)`, member, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.Exec(`INSERT INTO registry_webauthn_credentials (credential_id, user_id, name, credential, sign_count, created_at_ms) VALUES (?, ?, 'laptop', x'00', 0, 1)`, strings.Repeat("c", 22), member); err != nil {
		t.Fatal(err)
	}
	first, firstToken := issue(admin, member, false)
	if first.Code != http.StatusCreated || !strings.HasPrefix(firstToken, "prrst_") {
		t.Fatalf("issue recovery: %d %s", first.Code, first.Body.String())
	}
	// A newer link replaces the older one.
	_, token := issue(admin, member, true)
	if response := complete(firstToken, "synthetic-recovered-password-never-reuse"); response.Code != http.StatusNotFound {
		t.Fatalf("superseded link worked: %d", response.Code)
	}
	if response := complete(token, "short"); response.Code != http.StatusBadRequest {
		t.Fatalf("weak password accepted: %d", response.Code)
	}
	if response := complete(token, "synthetic-recovered-password-never-reuse"); response.Code != http.StatusNoContent {
		t.Fatalf("complete recovery: %d %s", response.Code, response.Body.String())
	}
	if response := complete(token, "synthetic-recovered-password-never-reuse"); response.Code != http.StatusNotFound {
		t.Fatalf("recovery link reused: %d", response.Code)
	}
	if response := login("forgetful.member", "synthetic-http-member-password"); response.Code == http.StatusOK {
		t.Fatal("old password still works")
	}
	if response := login("forgetful.member", "synthetic-recovered-password-never-reuse"); response.Code != http.StatusOK {
		t.Fatalf("new password: %d", response.Code)
	}
	if response := call(memberSession, http.MethodGet, "/api/v1/workspaces", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("session from before recovery still works: %d", response.Code)
	}
	for _, table := range []string{"registry_totp_credentials", "registry_webauthn_credentials"} {
		var count int
		if err := fixture.db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE user_id = ?`, member).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s kept %d rows after an MFA reset (%v)", table, count, err)
		}
	}

	// An account without a local password (for example Muira) can only have
	// its local factors reset, without setting a password.
	federated := uuid.NewString()
	if _, err := fixture.db.Exec(`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (?, 'Federated', ?, ?)`, federated, now, now); err != nil {
		t.Fatal(err)
	}
	if response, _ := issue(admin, federated, false); response.Code != http.StatusConflict {
		t.Fatalf("password recovery for an account without a password: %d", response.Code)
	}
	_, federatedToken := issue(admin, federated, true)
	if response := complete(federatedToken, "synthetic-recovered-password-never-reuse"); response.Code != http.StatusConflict {
		t.Fatalf("password set on an account without one: %d", response.Code)
	}
	if response := complete(federatedToken, ""); response.Code != http.StatusNoContent {
		t.Fatalf("MFA-only recovery: %d", response.Code)
	}

	// Local operator recovery of the last administrator.
	if err := fixture.service.RecoverAdministrator(ctx, "nobody.here", []byte("synthetic-recovered-password-never-reuse"), "operator"); err == nil {
		t.Fatal("recover-admin accepted an unknown login")
	}
	if err := fixture.service.RecoverAdministrator(ctx, "forgetful.member", []byte("synthetic-recovered-password-never-reuse"), "operator"); err == nil {
		t.Fatal("recover-admin promoted or recovered a non-administrator")
	}
	if err := fixture.service.RecoverAdministrator(ctx, authTestLogin, []byte("synthetic-admin-recovered-password"), "operator"); err != nil {
		t.Fatal(err)
	}
	if response := call(admin, http.MethodGet, "/api/v1/workspaces", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("administrator session survived recovery: %d", response.Code)
	}
	recovered := login(authTestLogin, "synthetic-admin-recovered-password")
	var stage loginResponse
	if err := json.Unmarshal(recovered.Body.Bytes(), &stage); err != nil || stage.Stage != "mfa_enrollment" {
		t.Fatalf("recovered administrator login: %d %s", recovered.Code, recovered.Body.String())
	}
	var audited int
	if err := fixture.db.QueryRow(`SELECT COUNT(*) FROM registry_audit_events WHERE action IN ('account.recovery.issued', 'account.recovery.completed', 'instance_admin.recovered')`).Scan(&audited); err != nil || audited < 6 {
		t.Fatalf("recovery audit events: %d %v", audited, err)
	}
}
