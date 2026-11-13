package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInvitationsCreateAccountsAndMemberships(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx := context.Background()
	var owner string
	if err := fixture.db.QueryRow(`SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "team", "Team")
	if err != nil {
		t.Fatal(err)
	}
	admin := muiraAdminMFACookies(t, fixture.handler)
	call := func(cookies map[string]*http.Cookie, method, path, body string) *httptest.ResponseRecorder {
		csrf := ""
		if cookies[csrfCookieName] != nil {
			csrf = cookies[csrfCookieName].Value
		}
		return authHTTPRequestWithCookies(fixture.handler, method, path, body, authTestOrigin, "registry.example", cookies, csrf)
	}
	invite := func(cookies map[string]*http.Cookie, role string) (invitationResponse, int) {
		t.Helper()
		response := call(cookies, http.MethodPost, "/api/v1/workspaces/"+workspace.ID+"/invitations", fmt.Sprintf(`{"role":%q}`, role))
		var body invitationResponse
		_ = json.Unmarshal(response.Body.Bytes(), &body)
		return body, response.Code
	}
	redeem := func(token, login string) *httptest.ResponseRecorder {
		return authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/invitations/redeem", fmt.Sprintf(`{"token":%q,"login_name":%q,"display_name":"Invited Person","password":"synthetic-invited-password-never-reuse"}`, token, login), authTestOrigin, "registry.example")
	}
	login := func(name string) *httptest.ResponseRecorder {
		return authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login", fmt.Sprintf(`{"login_name":%q,"password":"synthetic-invited-password-never-reuse"}`, name), authTestOrigin, "registry.example")
	}

	member, code := invite(admin, "member")
	if code != http.StatusCreated || !strings.HasPrefix(member.Token, "prinv_") {
		t.Fatalf("create invitation: %d %+v", code, member)
	}
	// Signup is closed by default: the invitation cannot create an account.
	if response := redeem(member.Token, "invited.member"); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "signup_closed") {
		t.Fatalf("redeem with signup closed: %d %s", response.Code, response.Body.String())
	}
	if response := call(admin, http.MethodPut, "/api/v1/admin/signup-policy", `{"policy":"open"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("open signup without email transport was accepted: %d", response.Code)
	}
	if response := call(admin, http.MethodPut, "/api/v1/admin/signup-policy", `{"policy":"invitations"}`); response.Code != http.StatusNoContent {
		t.Fatalf("enable signup by invitation: %d", response.Code)
	}
	if response := call(admin, http.MethodGet, "/api/v1/admin/signup-policy", ""); !strings.Contains(response.Body.String(), `"invitations"`) {
		t.Fatalf("signup policy: %s", response.Body.String())
	}
	if response := redeem(member.Token, "x"); response.Code != http.StatusBadRequest {
		t.Fatalf("invalid login name: %d", response.Code)
	}
	if response := redeem(member.Token, authTestLogin); response.Code != http.StatusConflict {
		t.Fatalf("taken login name: %d", response.Code)
	}
	redeemed := redeem(member.Token, "invited.member")
	if redeemed.Code != http.StatusCreated || !strings.Contains(redeemed.Body.String(), workspace.ID) {
		t.Fatalf("redeem: %d %s", redeemed.Code, redeemed.Body.String())
	}
	if response := redeem(member.Token, "invited.again"); response.Code != http.StatusNotFound {
		t.Fatalf("invitation reused: %d", response.Code)
	}
	signedIn := login("invited.member")
	var stage loginResponse
	if err := json.Unmarshal(signedIn.Body.Bytes(), &stage); err != nil || signedIn.Code != http.StatusOK || stage.Stage != "authenticated" {
		t.Fatalf("invited member login: %d %s", signedIn.Code, signedIn.Body.String())
	}
	memberCookies := assertSessionCookies(t, signedIn)
	if listed := call(memberCookies, http.MethodGet, "/api/v1/workspaces", ""); !strings.Contains(listed.Body.String(), workspace.ID) {
		t.Fatalf("invited member does not see the workspace: %s", listed.Body.String())
	}
	// Members cannot invite or list invitations.
	if _, code := invite(memberCookies, "member"); code != http.StatusForbidden {
		t.Fatalf("member created an invitation: %d", code)
	}

	// An administrator invitation leads to TOTP enrollment at first sign-in.
	administrator, code := invite(admin, "administrator")
	if code != http.StatusCreated {
		t.Fatal(code)
	}
	if response := redeem(administrator.Token, "invited.admin"); response.Code != http.StatusCreated {
		t.Fatalf("redeem administrator invitation: %d", response.Code)
	}
	adminLogin := login("invited.admin")
	if err := json.Unmarshal(adminLogin.Body.Bytes(), &stage); err != nil || stage.Stage != "mfa_enrollment" {
		t.Fatalf("invited administrator skipped MFA enrollment: %s", adminLogin.Body.String())
	}

	// Revoked invitations stop working; listing shows state, never tokens.
	revoked, _ := invite(admin, "member")
	if response := call(admin, http.MethodDelete, "/api/v1/workspaces/"+workspace.ID+"/invitations/"+revoked.InvitationID, ""); response.Code != http.StatusNoContent {
		t.Fatalf("revoke invitation: %d", response.Code)
	}
	if response := redeem(revoked.Token, "invited.revoked"); response.Code != http.StatusNotFound {
		t.Fatalf("revoked invitation redeemed: %d", response.Code)
	}
	listed := call(admin, http.MethodGet, "/api/v1/workspaces/"+workspace.ID+"/invitations", "")
	body := listed.Body.String()
	if listed.Code != http.StatusOK || strings.Contains(body, "prinv_") || !strings.Contains(body, `"state":"redeemed"`) || !strings.Contains(body, `"state":"revoked"`) {
		t.Fatalf("invitation list: %d %s", listed.Code, body)
	}

	// An existing account, such as one that signs in through Muira, accepts
	// an invitation while signed in.
	existing := seedHTTPUser(t, fixture, "existing.user")
	existingLogin := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login", `{"login_name":"existing.user","password":"synthetic-http-member-password"}`, authTestOrigin, "registry.example")
	existingCookies := assertSessionCookies(t, existingLogin)
	join, _ := invite(admin, "member")
	if response := call(existingCookies, http.MethodPost, "/api/v1/invitations/accept", fmt.Sprintf(`{"token":%q}`, join.Token)); response.Code != http.StatusOK {
		t.Fatalf("accept invitation: %d %s", response.Code, response.Body.String())
	}
	second, _ := invite(admin, "member")
	if response := call(existingCookies, http.MethodPost, "/api/v1/invitations/accept", fmt.Sprintf(`{"token":%q}`, second.Token)); response.Code != http.StatusConflict {
		t.Fatalf("second accept for a member: %d", response.Code)
	}
	if response := call(existingCookies, http.MethodPost, "/api/v1/invitations/accept", `{"token":"prinv_garbage"}`); response.Code != http.StatusNotFound {
		t.Fatalf("garbage token: %d", response.Code)
	}
	var role string
	if err := fixture.db.QueryRow(`SELECT role FROM registry_workspace_memberships WHERE workspace_id = ? AND user_id = ?`, workspace.ID, existing).Scan(&role); err != nil || role != "member" {
		t.Fatalf("accepted membership: %q %v", role, err)
	}
	// Membership grants nothing in repositories.
	var grants int
	if err := fixture.db.QueryRow(`SELECT COUNT(*) FROM registry_repository_grants WHERE user_id = ?`, existing).Scan(&grants); err != nil || grants != 0 {
		t.Fatalf("invitation created repository grants: %d %v", grants, err)
	}

	// An administrator can only invite members, and their pending invitations
	// stop working once they lose the role.
	if err := fixture.workspaceService.SetMembershipRole(ctx, owner, workspace.ID, existing, "administrator"); err != nil {
		t.Fatal(err)
	}
	// Elevated sessions need recent MFA; drive the service directly.
	if _, err := fixture.workspaceService.CreateInvitation(ctx, existing, workspace.ID, "administrator", 0); err == nil {
		t.Fatal("workspace administrator invited an administrator")
	}
	pending, err := fixture.workspaceService.CreateInvitation(ctx, existing, workspace.ID, "member", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.workspaceService.SetMembershipRole(ctx, owner, workspace.ID, existing, "member"); err != nil {
		t.Fatal(err)
	}
	if response := redeem(pending.Token, "after.demotion"); response.Code != http.StatusNotFound {
		t.Fatalf("invitation from a demoted administrator still worked: %d", response.Code)
	}
}
