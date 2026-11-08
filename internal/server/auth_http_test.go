//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
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

	"github.com/google/uuid"
	"private-registry/internal/artifacts"
	"private-registry/internal/auth"
	"private-registry/internal/bootstrap"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/jobs"
	"private-registry/internal/migrations"
	"private-registry/internal/password"
	"private-registry/internal/repositories"
	"private-registry/internal/secrets"
	"private-registry/internal/sessions"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
)

const (
	authTestOrigin      = "https://registry.example"
	authTestAssetOrigin = "https://assets.example"
	authTestLogin       = "http.admin"
	authTestPassword    = "synthetic-auth-http-password-never-reuse"
)

type authHTTPFixture struct {
	handler           http.Handler
	service           *auth.Service
	workspaceService  *workspaces.Service
	repositoryService *repositories.Service
	artifactService   *artifacts.Service
	db                *sql.DB
}

func newAuthHTTPFixture(t *testing.T) authHTTPFixture {
	t.Helper()
	return newAuthHTTPFixtureWithConfig(t, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin})
}

func newAuthHTTPFixtureWithProxies(t *testing.T, proxies []netip.Prefix) authHTTPFixture {
	t.Helper()
	return newAuthHTTPFixtureWithConfig(t, AuthHTTPConfig{
		CanonicalOrigin: authTestOrigin,
		AssetOrigin:     authTestAssetOrigin,
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
	workspaceService, err := workspaces.New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	repositoryService, err := repositories.New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	objectStore, err := storage.NewFileSystem(filepath.Join(dataDir, "object-store"))
	if err != nil {
		t.Fatal(err)
	}
	artifactService, err := artifacts.New(db, config.SQLite, repositoryService, objectStore, artifacts.Options{
		MaxUploadBytes:       1 << 20,
		MaxConcurrentUploads: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewHealth(db), service, workspaceService, repositoryService, artifactService, authConfig)
	if err != nil {
		t.Fatal(err)
	}
	return authHTTPFixture{
		handler:           handler,
		service:           service,
		workspaceService:  workspaceService,
		repositoryService: repositoryService,
		artifactService:   artifactService,
		db:                db,
	}
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

func TestAuthHTTPRejectsWrongOriginsAndKeepsContentRoutesUnavailable(t *testing.T) {
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
	for _, path := range []string{"/api/v1/admin", "/packages/private"} {
		request := httptest.NewRequest(http.MethodGet, "https://registry.example"+path, nil)
		request.Host = "registry.example"
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("unimplemented protected route %q became reachable: status=%d", path, response.Code)
		}
	}
	workspacesRequest := httptest.NewRequest(http.MethodGet, "https://registry.example/api/v1/workspaces", nil)
	workspacesRequest.Host = "registry.example"
	workspacesResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(workspacesResponse, workspacesRequest)
	if workspacesResponse.Code != http.StatusUnauthorized {
		t.Fatalf("workspace route accepted an unauthenticated request: status=%d", workspacesResponse.Code)
	}
}

func TestAuthHTTPWorkspaceIsolationMFAAndVoluntaryEnrollment(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx := context.Background()
	var administratorID string
	if err := fixture.db.QueryRowContext(ctx, "SELECT user_id FROM registry_instance_admins").Scan(&administratorID); err != nil {
		t.Fatal(err)
	}
	firstWorkspace, err := fixture.workspaceService.CreateWorkspace(ctx, administratorID, "http-first", "HTTP First")
	if err != nil {
		t.Fatal(err)
	}
	removedWorkspace, err := fixture.workspaceService.CreateWorkspace(ctx, administratorID, "http-removed", "HTTP Removed")
	if err != nil {
		t.Fatal(err)
	}
	memberID := seedHTTPUser(t, fixture, "http.member")
	memberTimestamp := time.Now().UTC().Format(time.RFC3339Nano)
	for _, membership := range []struct {
		workspaceID string
		status      string
	}{
		{workspaceID: firstWorkspace.ID, status: "active"},
		{workspaceID: removedWorkspace.ID, status: "removed"},
	} {
		if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_workspace_memberships
			(workspace_id, user_id, role, status, created_by, created_at, updated_at)
			VALUES (?, ?, 'member', ?, ?, ?, ?)`, membership.workspaceID, memberID, membership.status,
			administratorID, memberTimestamp, memberTimestamp); err != nil {
			t.Fatal(err)
		}
	}
	if err := fixture.workspaceService.SetCreationPolicy(ctx, administratorID, workspaces.CreationAnyUser); err != nil {
		t.Fatal(err)
	}

	login := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login",
		`{"login_name":"http.member","password":"synthetic-http-member-password"}`, authTestOrigin, "registry.example")
	if login.Code != http.StatusOK {
		t.Fatalf("ordinary member login failed: status=%d body=%s", login.Code, login.Body.String())
	}
	memberCookies := assertSessionCookies(t, login)
	var loginStage loginResponse
	if err := json.Unmarshal(login.Body.Bytes(), &loginStage); err != nil {
		t.Fatal(err)
	}
	if loginStage.Stage != string(auth.StageAuthenticated) {
		t.Fatalf("ordinary member received an unexpected login stage: %+v", loginStage)
	}

	listed := authHTTPRequestWithCookies(fixture.handler, http.MethodGet,
		"/api/v1/workspaces", "", "", "registry.example", memberCookies, "")
	if listed.Code != http.StatusOK {
		t.Fatalf("workspace listing failed: status=%d body=%s", listed.Code, listed.Body.String())
	}
	var listing workspaceListResponse
	if err := json.Unmarshal(listed.Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	if listing.HasMore || listing.NextCursor != "" || len(listing.Workspaces) != 1 ||
		listing.Workspaces[0].WorkspaceID != firstWorkspace.ID || listing.Workspaces[0].Role != "member" {
		t.Fatalf("workspace listing leaked a removed or unjoined workspace: %+v", listing)
	}

	createBody := `{"slug":"http-created","display_name":"HTTP Created"}`
	missingCSRF := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, "/api/v1/workspaces",
		createBody, authTestOrigin, "registry.example", memberCookies, "")
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("workspace creation accepted a write without CSRF: status=%d body=%s", missingCSRF.Code, missingCSRF.Body.String())
	}
	standardCreation := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, "/api/v1/workspaces",
		createBody, authTestOrigin, "registry.example", memberCookies, memberCookies[csrfCookieName].Value)
	if standardCreation.Code != http.StatusForbidden || !strings.Contains(standardCreation.Body.String(), "mfa_required") {
		t.Fatalf("standard session created a workspace: status=%d body=%s", standardCreation.Code, standardCreation.Body.String())
	}

	startEnrollment := authHTTPRequestWithCookies(fixture.handler, http.MethodPost,
		"/api/v1/auth/mfa/enrollment/start", "", authTestOrigin, "registry.example",
		memberCookies, memberCookies[csrfCookieName].Value)
	if startEnrollment.Code != http.StatusOK {
		t.Fatalf("voluntary MFA enrollment failed: status=%d body=%s", startEnrollment.Code, startEnrollment.Body.String())
	}
	var enrollment enrollmentResponse
	if err := json.Unmarshal(startEnrollment.Body.Bytes(), &enrollment); err != nil {
		t.Fatal(err)
	}
	if enrollment.Secret == "" || enrollment.OTPAuthURL == "" {
		t.Fatalf("voluntary enrollment response was incomplete: %+v", enrollment)
	}
	enrollmentCookies := assertSessionCookies(t, startEnrollment)
	restrictedListing := authHTTPRequestWithCookies(fixture.handler, http.MethodGet,
		"/api/v1/workspaces", "", "", "registry.example", enrollmentCookies, "")
	if restrictedListing.Code != http.StatusForbidden ||
		!strings.Contains(restrictedListing.Body.String(), "authentication_incomplete") {
		t.Fatalf("enrollment-only session accessed the workspace listing: status=%d body=%s",
			restrictedListing.Code, restrictedListing.Body.String())
	}
	if _, err := fixture.service.ValidateSession(ctx, memberCookies[sessionCookieName].Value); !errors.Is(err, sessions.ErrSessionUnavailable) {
		t.Fatalf("pre-enrollment standard session remained valid: %v", err)
	}

	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	confirmationCode := authHTTPOTP(secret, time.Now().Unix()/30)
	completedEnrollment := authHTTPRequestWithCookies(fixture.handler, http.MethodPost,
		"/api/v1/auth/mfa/enrollment/complete", fmt.Sprintf(`{"code":%q}`, confirmationCode),
		authTestOrigin, "registry.example", enrollmentCookies, enrollmentCookies[csrfCookieName].Value)
	if completedEnrollment.Code != http.StatusOK {
		t.Fatalf("voluntary MFA confirmation failed: status=%d body=%s", completedEnrollment.Code, completedEnrollment.Body.String())
	}
	mfaCookies := assertSessionCookies(t, completedEnrollment)

	challengeLogin := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login",
		`{"login_name":"http.member","password":"synthetic-http-member-password"}`, authTestOrigin, "registry.example")
	if challengeLogin.Code != http.StatusOK {
		t.Fatalf("MFA challenge login failed: status=%d body=%s", challengeLogin.Code, challengeLogin.Body.String())
	}
	var challengeStage loginResponse
	if err := json.Unmarshal(challengeLogin.Body.Bytes(), &challengeStage); err != nil {
		t.Fatal(err)
	}
	if challengeStage.Stage != string(auth.StageMFAChallenge) {
		t.Fatalf("user with active factor did not receive a challenge session: %+v", challengeStage)
	}
	challengeCookies := assertSessionCookies(t, challengeLogin)
	challengeListing := authHTTPRequestWithCookies(fixture.handler, http.MethodGet,
		"/api/v1/workspaces", "", "", "registry.example", challengeCookies, "")
	if challengeListing.Code != http.StatusForbidden ||
		!strings.Contains(challengeListing.Body.String(), "authentication_incomplete") {
		t.Fatalf("MFA-challenge session accessed the workspace listing: status=%d body=%s",
			challengeListing.Code, challengeListing.Body.String())
	}

	created := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, "/api/v1/workspaces",
		createBody, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if created.Code != http.StatusCreated {
		t.Fatalf("MFA-authenticated workspace creation failed: status=%d body=%s", created.Code, created.Body.String())
	}
	var createdWorkspace workspaceItemResponse
	if err := json.Unmarshal(created.Body.Bytes(), &createdWorkspace); err != nil {
		t.Fatal(err)
	}
	if createdWorkspace.Slug != "http-created" || createdWorkspace.Role != "owner" || createdWorkspace.WorkspaceID == "" {
		t.Fatalf("created workspace did not return owner membership: %+v", createdWorkspace)
	}
	staleMFATimestamp := time.Now().UTC().Add(-workspaceCreationMFAMaxAge - time.Minute).Format(time.RFC3339Nano)
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_auth_sessions
		SET mfa_verified_at = ? WHERE user_id = ? AND level = 'mfa' AND revoked_at IS NULL`,
		staleMFATimestamp, memberID); err != nil {
		t.Fatal(err)
	}
	staleMFACreation := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, "/api/v1/workspaces",
		`{"slug":"stale-mfa","display_name":"Stale MFA"}`, authTestOrigin,
		"registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if staleMFACreation.Code != http.StatusForbidden ||
		!strings.Contains(staleMFACreation.Body.String(), "reauthentication_required") {
		t.Fatalf("stale MFA authentication was accepted for workspace creation: status=%d body=%s",
			staleMFACreation.Code, staleMFACreation.Body.String())
	}

	listed = authHTTPRequestWithCookies(fixture.handler, http.MethodGet,
		"/api/v1/workspaces", "", "", "registry.example", mfaCookies, "")
	if listed.Code != http.StatusOK {
		t.Fatalf("workspace relisting failed: status=%d body=%s", listed.Code, listed.Body.String())
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	if listing.HasMore || len(listing.Workspaces) != 2 {
		t.Fatalf("member listing did not show exactly the active membership and new owner workspace: %+v", listing)
	}
}

func TestAuthHTTPMembershipManagementRequiresRecentMFAAndProtectsOwner(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx := context.Background()
	var ownerID string
	if err := fixture.db.QueryRowContext(ctx, "SELECT user_id FROM registry_instance_admins").Scan(&ownerID); err != nil {
		t.Fatal(err)
	}

	login := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login",
		fmt.Sprintf(`{"login_name":%q,"password":%q}`, authTestLogin, authTestPassword),
		authTestOrigin, "registry.example")
	if login.Code != http.StatusOK {
		t.Fatalf("administrator login failed: status=%d body=%s", login.Code, login.Body.String())
	}
	enrollmentCookies := assertSessionCookies(t, login)
	startEnrollment := authHTTPRequestWithCookies(fixture.handler, http.MethodPost,
		"/api/v1/auth/mfa/enrollment", "", authTestOrigin, "registry.example",
		enrollmentCookies, enrollmentCookies[csrfCookieName].Value)
	if startEnrollment.Code != http.StatusOK {
		t.Fatalf("administrator MFA enrollment did not start: status=%d body=%s",
			startEnrollment.Code, startEnrollment.Body.String())
	}
	var enrollment enrollmentResponse
	if err := json.Unmarshal(startEnrollment.Body.Bytes(), &enrollment); err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	completeEnrollment := authHTTPRequestWithCookies(fixture.handler, http.MethodPost,
		"/api/v1/auth/mfa/enrollment/complete",
		fmt.Sprintf(`{"code":%q}`, authHTTPOTP(secret, time.Now().Unix()/30)),
		authTestOrigin, "registry.example", enrollmentCookies, enrollmentCookies[csrfCookieName].Value)
	if completeEnrollment.Code != http.StatusOK {
		t.Fatalf("administrator MFA enrollment failed: status=%d body=%s",
			completeEnrollment.Code, completeEnrollment.Body.String())
	}
	mfaCookies := assertSessionCookies(t, completeEnrollment)

	workspaceResponse := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, "/api/v1/workspaces",
		`{"slug":"membership-api","display_name":"Membership API"}`, authTestOrigin,
		"registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if workspaceResponse.Code != http.StatusCreated {
		t.Fatalf("workspace creation failed: status=%d body=%s", workspaceResponse.Code, workspaceResponse.Body.String())
	}
	var createdWorkspace workspaceItemResponse
	if err := json.Unmarshal(workspaceResponse.Body.Bytes(), &createdWorkspace); err != nil {
		t.Fatal(err)
	}
	repositoriesPath := fmt.Sprintf("/api/v1/workspaces/%s/repositories", createdWorkspace.WorkspaceID)
	createRepository := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, repositoriesPath,
		`{"slug":"private-packages","display_name":"Private Packages"}`, authTestOrigin,
		"registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if createRepository.Code != http.StatusCreated {
		t.Fatalf("MFA-authenticated repository creation failed: status=%d body=%s",
			createRepository.Code, createRepository.Body.String())
	}
	var createdRepository repositoryItemResponse
	if err := json.Unmarshal(createRepository.Body.Bytes(), &createdRepository); err != nil {
		t.Fatal(err)
	}
	if createdRepository.Visibility != string(repositories.VisibilityPrivate) || createdRepository.RepositoryID == "" || createdRepository.Format != string(repositories.FormatGeneric) {
		t.Fatalf("new repository was not private by default: %+v", createdRepository)
	}
	repositoryPath := repositoriesPath + "/" + createdRepository.RepositoryID
	updateRepository := authHTTPRequestWithCookies(fixture.handler, http.MethodPatch, repositoryPath,
		`{"display_name":"Private Package Mirror"}`, authTestOrigin, "registry.example",
		mfaCookies, mfaCookies[csrfCookieName].Value)
	if updateRepository.Code != http.StatusNoContent {
		t.Fatalf("workspace owner could not update repository display name: status=%d body=%s",
			updateRepository.Code, updateRepository.Body.String())
	}
	currentVisibilityPolicy := authHTTPRequestWithCookies(fixture.handler, http.MethodGet,
		"/api/v1/admin/repository-visibility-policy", "", "", "registry.example", mfaCookies, "")
	if currentVisibilityPolicy.Code != http.StatusOK ||
		!strings.Contains(currentVisibilityPolicy.Body.String(), string(repositories.PolicyPrivateOnly)) {
		t.Fatalf("initial visibility policy was unavailable or not private-only: status=%d body=%s",
			currentVisibilityPolicy.Code, currentVisibilityPolicy.Body.String())
	}
	setPolicy := authHTTPRequestWithCookies(fixture.handler, http.MethodPut,
		"/api/v1/admin/repository-visibility-policy", `{"policy":"all"}`,
		authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if setPolicy.Code != http.StatusNoContent {
		t.Fatalf("instance administrator could not enable visibility modes: status=%d body=%s",
			setPolicy.Code, setPolicy.Body.String())
	}
	visibilityPath := repositoryPath + "/visibility"
	missingPublicConfirmation := authHTTPRequestWithCookies(fixture.handler, http.MethodPatch, visibilityPath,
		`{"visibility":"listed"}`, authTestOrigin, "registry.example", mfaCookies,
		mfaCookies[csrfCookieName].Value)
	if missingPublicConfirmation.Code != http.StatusPreconditionFailed ||
		!strings.Contains(missingPublicConfirmation.Body.String(), "public_visibility_confirmation_required") {
		t.Fatalf("public visibility change did not require explicit confirmation: status=%d body=%s",
			missingPublicConfirmation.Code, missingPublicConfirmation.Body.String())
	}
	setListed := authHTTPRequestWithCookies(fixture.handler, http.MethodPatch, visibilityPath,
		`{"visibility":"listed","confirm_public":true}`, authTestOrigin,
		"registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if setListed.Code != http.StatusNoContent {
		t.Fatalf("workspace owner could not confirm listed visibility: status=%d body=%s",
			setListed.Code, setListed.Body.String())
	}
	restrictPolicy := authHTTPRequestWithCookies(fixture.handler, http.MethodPut,
		"/api/v1/admin/repository-visibility-policy", `{"policy":"private_only"}`,
		authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if restrictPolicy.Code != http.StatusNoContent {
		t.Fatalf("instance administrator could not restrict future visibility changes: status=%d body=%s",
			restrictPolicy.Code, restrictPolicy.Body.String())
	}
	repositoryListing := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, repositoriesPath,
		"", "", "registry.example", mfaCookies, "")
	if repositoryListing.Code != http.StatusOK {
		t.Fatalf("workspace owner could not list repositories: status=%d body=%s",
			repositoryListing.Code, repositoryListing.Body.String())
	}
	var listedRepositories repositoryListResponse
	if err := json.Unmarshal(repositoryListing.Body.Bytes(), &listedRepositories); err != nil {
		t.Fatal(err)
	}
	if len(listedRepositories.Repositories) != 1 ||
		listedRepositories.Repositories[0].Visibility != string(repositories.VisibilityListed) {
		t.Fatalf("policy restriction silently converted an existing repository: %+v", listedRepositories)
	}
	createGo := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, repositoriesPath,
		`{"slug":"go-modules","display_name":"Go Modules","format":"go"}`, authTestOrigin,
		"registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	var goRepository repositoryItemResponse
	if createGo.Code != http.StatusCreated || json.Unmarshal(createGo.Body.Bytes(), &goRepository) != nil || goRepository.Format != "go" {
		t.Fatalf("Go repository creation status=%d body=%s", createGo.Code, createGo.Body.String())
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, ownerID, createdWorkspace.WorkspaceID, goRepository.RepositoryID, ownerID, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	wrongFormatPath := repositoriesPath + "/" + goRepository.RepositoryID + "/artifacts/uploads"
	wrongFormatBody := `{"collection":"fixture","version":"v1","path":"file.bin","content_type":"application/octet-stream","size":1,"sha256":"` + strings.Repeat("a", 64) + `"}`
	wrongFormat := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, wrongFormatPath, wrongFormatBody, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if wrongFormat.Code != http.StatusConflict || !strings.Contains(wrongFormat.Body.String(), `"repository_format_mismatch"`) {
		t.Fatalf("generic upload into Go repository status=%d body=%s", wrongFormat.Code, wrongFormat.Body.String())
	}
	for _, format := range []string{`null`, `"unsupported"`, `""`} {
		bad := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, repositoriesPath,
			`{"slug":"bad-format","display_name":"Bad","format":`+format+`}`, authTestOrigin,
			"registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("invalid repository format %s status=%d", format, bad.Code)
		}
	}
	setPrivate := authHTTPRequestWithCookies(fixture.handler, http.MethodPatch, visibilityPath,
		`{"visibility":"private"}`, authTestOrigin, "registry.example", mfaCookies,
		mfaCookies[csrfCookieName].Value)
	if setPrivate.Code != http.StatusNoContent {
		t.Fatalf("workspace owner could not make the repository private: status=%d body=%s",
			setPrivate.Code, setPrivate.Body.String())
	}
	targetID := seedHTTPUser(t, fixture, "http.membership-target")
	memberPath := fmt.Sprintf("/api/v1/workspaces/%s/members/%s", createdWorkspace.WorkspaceID, targetID)

	targetLogin := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login",
		`{"login_name":"http.membership-target","password":"synthetic-http-member-password"}`,
		authTestOrigin, "registry.example")
	if targetLogin.Code != http.StatusOK {
		t.Fatalf("target user login failed: status=%d body=%s", targetLogin.Code, targetLogin.Body.String())
	}
	targetCookies := assertSessionCookies(t, targetLogin)
	selfElevation := authHTTPRequestWithCookies(fixture.handler, http.MethodPut, memberPath,
		`{"role":"owner"}`, authTestOrigin, "registry.example", targetCookies,
		targetCookies[csrfCookieName].Value)
	if selfElevation.Code != http.StatusForbidden || !strings.Contains(selfElevation.Body.String(), "mfa_required") {
		t.Fatalf("standard session changed membership: status=%d body=%s", selfElevation.Code, selfElevation.Body.String())
	}

	missingCSRF := authHTTPRequestWithCookies(fixture.handler, http.MethodPut, memberPath,
		`{"role":"member"}`, authTestOrigin, "registry.example", mfaCookies, "")
	if missingCSRF.Code != http.StatusForbidden || !strings.Contains(missingCSRF.Body.String(), "csrf_failed") {
		t.Fatalf("membership mutation accepted a missing CSRF token: status=%d body=%s",
			missingCSRF.Code, missingCSRF.Body.String())
	}
	addMember := authHTTPRequestWithCookies(fixture.handler, http.MethodPut, memberPath,
		`{"role":"member"}`, authTestOrigin, "registry.example", mfaCookies,
		mfaCookies[csrfCookieName].Value)
	if addMember.Code != http.StatusNoContent {
		t.Fatalf("owner could not add a member: status=%d body=%s", addMember.Code, addMember.Body.String())
	}
	grantPath := fmt.Sprintf("%s/grants/%s/reader", repositoryPath, targetID)
	missingGrantCSRF := authHTTPRequestWithCookies(fixture.handler, http.MethodPut, grantPath,
		"", authTestOrigin, "registry.example", mfaCookies, "")
	if missingGrantCSRF.Code != http.StatusForbidden || !strings.Contains(missingGrantCSRF.Body.String(), "csrf_failed") {
		t.Fatalf("repository grant mutation accepted a missing CSRF token: status=%d body=%s",
			missingGrantCSRF.Code, missingGrantCSRF.Body.String())
	}
	grantReader := authHTTPRequestWithCookies(fixture.handler, http.MethodPut, grantPath,
		"", authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if grantReader.Code != http.StatusOK {
		t.Fatalf("owner could not explicitly grant reader: status=%d body=%s", grantReader.Code, grantReader.Body.String())
	}
	var grantResponse repositoryGrantItemResponse
	if err := json.Unmarshal(grantReader.Body.Bytes(), &grantResponse); err != nil {
		t.Fatal(err)
	}
	if grantResponse.UserID != targetID || grantResponse.Role != string(repositories.GrantReader) || grantResponse.GrantID == "" {
		t.Fatalf("repository grant endpoint returned an unexpected grant: %+v", grantResponse)
	}
	duplicateGrant := authHTTPRequestWithCookies(fixture.handler, http.MethodPut, grantPath,
		"", authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if duplicateGrant.Code != http.StatusOK || !strings.Contains(duplicateGrant.Body.String(), grantResponse.GrantID) {
		t.Fatalf("repeated grant request was not idempotent: status=%d body=%s", duplicateGrant.Code, duplicateGrant.Body.String())
	}
	grantListingPath := repositoryPath + "/grants"
	grantListing := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, grantListingPath,
		"", "", "registry.example", mfaCookies, "")
	if grantListing.Code != http.StatusOK || !strings.Contains(grantListing.Body.String(), grantResponse.GrantID) {
		t.Fatalf("workspace owner could not list repository grants: status=%d body=%s",
			grantListing.Code, grantListing.Body.String())
	}
	memberGrantListing := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, grantListingPath,
		"", "", "registry.example", targetCookies, "")
	if memberGrantListing.Code != http.StatusForbidden {
		t.Fatalf("ordinary member listed repository grants: status=%d body=%s",
			memberGrantListing.Code, memberGrantListing.Body.String())
	}
	revokeReader := authHTTPRequestWithCookies(fixture.handler, http.MethodDelete, grantPath,
		"", authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if revokeReader.Code != http.StatusNoContent {
		t.Fatalf("owner could not revoke reader grant: status=%d body=%s", revokeReader.Code, revokeReader.Body.String())
	}
	if allowed, err := fixture.repositoryService.HasRepositoryGrant(
		ctx, targetID, createdWorkspace.WorkspaceID, createdRepository.RepositoryID, repositories.GrantReader); err != nil || allowed {
		t.Fatalf("revoked HTTP grant remained effective: allowed=%t err=%v", allowed, err)
	}
	grantAdministrator := authHTTPRequestWithCookies(fixture.handler, http.MethodPut, memberPath,
		`{"role":"administrator"}`, authTestOrigin, "registry.example", mfaCookies,
		mfaCookies[csrfCookieName].Value)
	if grantAdministrator.Code != http.StatusNoContent {
		t.Fatalf("owner could not change a membership role: status=%d body=%s",
			grantAdministrator.Code, grantAdministrator.Body.String())
	}

	lastOwnerRemoval := authHTTPRequestWithCookies(fixture.handler, http.MethodDelete,
		fmt.Sprintf("/api/v1/workspaces/%s/members/%s", createdWorkspace.WorkspaceID, ownerID),
		"", authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if lastOwnerRemoval.Code != http.StatusConflict || !strings.Contains(lastOwnerRemoval.Body.String(), "last_owner_required") {
		t.Fatalf("last owner was removed: status=%d body=%s", lastOwnerRemoval.Code, lastOwnerRemoval.Body.String())
	}

	staleMFATimestamp := time.Now().UTC().Add(-workspaceCreationMFAMaxAge - time.Minute).Format(time.RFC3339Nano)
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_auth_sessions
		SET mfa_verified_at = ? WHERE user_id = ? AND level = 'mfa' AND revoked_at IS NULL`,
		staleMFATimestamp, ownerID); err != nil {
		t.Fatal(err)
	}
	staleMutation := authHTTPRequestWithCookies(fixture.handler, http.MethodDelete, memberPath,
		"", authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if staleMutation.Code != http.StatusForbidden ||
		!strings.Contains(staleMutation.Body.String(), "reauthentication_required") {
		t.Fatalf("stale MFA session changed a membership: status=%d body=%s",
			staleMutation.Code, staleMutation.Body.String())
	}

	var currentRole string
	if err := fixture.db.QueryRowContext(ctx, `SELECT role FROM registry_workspace_memberships
		WHERE workspace_id = ? AND user_id = ?`, createdWorkspace.WorkspaceID, targetID).Scan(&currentRole); err != nil {
		t.Fatal(err)
	}
	if currentRole != workspaces.RoleAdministrator {
		t.Fatalf("stale membership request changed the persisted role: %q", currentRole)
	}
	if err := fixture.workspaceService.SetMembershipRole(ctx, ownerID, createdWorkspace.WorkspaceID,
		targetID, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	memberRepositoryList := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, repositoriesPath,
		"", "", "registry.example", targetCookies, "")
	if memberRepositoryList.Code != http.StatusForbidden {
		t.Fatalf("workspace membership alone granted repository metadata access: status=%d body=%s",
			memberRepositoryList.Code, memberRepositoryList.Body.String())
	}
	memberPolicyRead := authHTTPRequestWithCookies(fixture.handler, http.MethodGet,
		"/api/v1/admin/repository-visibility-policy", "", "", "registry.example", targetCookies, "")
	if memberPolicyRead.Code != http.StatusForbidden {
		t.Fatalf("non-administrator read installation visibility policy: status=%d body=%s",
			memberPolicyRead.Code, memberPolicyRead.Body.String())
	}
}

func TestPublicAssetCORSRejectsUnsafeOrigins(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	for _, origin := range []string{"*", "null", "http://consumer.example", "https://consumer.example/path", "https://user@consumer.example"} {
		cfg := AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin, PublicAssetCORSOrigins: []string{origin}}
		if _, err := NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, cfg); err == nil {
			t.Fatalf("unsafe CORS origin %q was accepted", origin)
		}
	}
}

func TestAuthHTTPGenericArtifactPublicationRequiresCurrentPublisherGrant(t *testing.T) {
	fixture := newAuthHTTPFixtureWithConfig(t, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin, PublicAssetCORSOrigins: []string{"https://consumer.example"}})
	ctx := context.Background()
	var ownerID string
	if err := fixture.db.QueryRowContext(ctx, "SELECT user_id FROM registry_instance_admins").Scan(&ownerID); err != nil {
		t.Fatal("read administrator identity:", err)
	}
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, ownerID, "artifact-http", "Artifact HTTP")
	if err != nil {
		t.Fatal("create test workspace:", err)
	}
	repository, err := fixture.repositoryService.Create(ctx, ownerID, workspace.ID, "artifact-files", "Artifact Files")
	if err != nil {
		t.Fatal("create test repository:", err)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, ownerID, workspace.ID, repository.ID,
		ownerID, repositories.GrantPublisher); err != nil {
		t.Fatal("explicitly grant publisher role:", err)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, ownerID, workspace.ID, repository.ID,
		ownerID, repositories.GrantReader); err != nil {
		t.Fatal("explicitly grant reader role:", err)
	}
	cargoRepository := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'cargo-fixture', 'Cargo fixture', ?, 'now', 'now', 'cargo')`, cargoRepository, workspace.ID, ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, ownerID, workspace.ID, cargoRepository, ownerID, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	cargoIssuePath := fmt.Sprintf("/api/v1/workspaces/%s/repositories/%s/cargo-write-tokens", workspace.ID, cargoRepository)

	login := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login",
		fmt.Sprintf(`{"login_name":%q,"password":%q}`, authTestLogin, authTestPassword),
		authTestOrigin, "registry.example")
	if login.Code != http.StatusOK {
		t.Fatalf("administrator login failed: status=%d body=%s", login.Code, login.Body.String())
	}
	enrollmentCookies := assertSessionCookies(t, login)
	preMFAIssuePath := fmt.Sprintf("/api/v1/workspaces/%s/repositories/%s/personal-read-tokens", workspace.ID, repository.ID)
	preMFAIssue := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, preMFAIssuePath, `{}`, authTestOrigin, "registry.example", enrollmentCookies, enrollmentCookies[csrfCookieName].Value)
	if preMFAIssue.Code == http.StatusCreated {
		t.Fatal("personal token was issued before MFA")
	}
	if preMFA := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, cargoIssuePath, `{}`, authTestOrigin, "registry.example", enrollmentCookies, enrollmentCookies[csrfCookieName].Value); preMFA.Code == http.StatusCreated {
		t.Fatal("Cargo write token was issued before MFA")
	}
	beginEnrollment := authHTTPRequestWithCookies(fixture.handler, http.MethodPost,
		"/api/v1/auth/mfa/enrollment", "", authTestOrigin, "registry.example",
		enrollmentCookies, enrollmentCookies[csrfCookieName].Value)
	if beginEnrollment.Code != http.StatusOK {
		t.Fatalf("MFA enrollment did not start: status=%d body=%s", beginEnrollment.Code, beginEnrollment.Body.String())
	}
	var enrollment enrollmentResponse
	if err := json.Unmarshal(beginEnrollment.Body.Bytes(), &enrollment); err != nil {
		t.Fatal("decode MFA enrollment:", err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal("decode MFA secret:", err)
	}
	defer clear(secret)
	completeEnrollment := authHTTPRequestWithCookies(fixture.handler, http.MethodPost,
		"/api/v1/auth/mfa/enrollment/complete",
		fmt.Sprintf(`{"code":%q}`, authHTTPOTP(secret, time.Now().Unix()/30)),
		authTestOrigin, "registry.example", enrollmentCookies, enrollmentCookies[csrfCookieName].Value)
	if completeEnrollment.Code != http.StatusOK {
		t.Fatalf("MFA enrollment failed: status=%d body=%s", completeEnrollment.Code, completeEnrollment.Body.String())
	}
	mfaCookies := assertSessionCookies(t, completeEnrollment)
	queue, err := jobs.New(fixture.db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	jobNow := time.Now().UTC()
	deadID, err := queue.Enqueue(ctx, "synthetic-private-key", "expire-generic-uploads", `{"token":"synthetic-secret"}`, 1, jobNow, jobNow)
	if err != nil {
		t.Fatal("enqueue synthetic failed job:", err)
	}
	claimed, err := queue.Claim(ctx, "expire-generic-uploads", jobNow, time.Minute)
	if err != nil {
		t.Fatal("claim synthetic failed job:", err)
	}
	if err := queue.Finish(ctx, deadID, claimed.LeaseToken, false, jobNow.Add(time.Second), jobNow.Add(2*time.Second)); err != nil {
		t.Fatal("fail synthetic job:", err)
	}
	listJobs := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, "/api/v1/admin/jobs/dead", "", authTestOrigin, "registry.example", mfaCookies, "")
	var deadList deadJobListResponse
	if listJobs.Code != http.StatusOK || json.Unmarshal(listJobs.Body.Bytes(), &deadList) != nil || len(deadList.Jobs) != 1 || deadList.Jobs[0].ID != deadID || deadList.Jobs[0].Kind != "expire-generic-uploads" || strings.Contains(listJobs.Body.String(), "synthetic-secret") || strings.Contains(listJobs.Body.String(), "synthetic-private-key") {
		t.Fatalf("dead-job list = status %d body %s", listJobs.Code, listJobs.Body.String())
	}
	retryPath := "/api/v1/admin/jobs/" + deadID + "/retry"
	retryBody := fmt.Sprintf(`{"expected_revision":%d}`, deadList.Jobs[0].Revision)
	noJobCSRF := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, retryPath, retryBody, authTestOrigin, "registry.example", mfaCookies, "")
	if noJobCSRF.Code != http.StatusForbidden {
		t.Fatalf("dead-job retry without CSRF = %d", noJobCSRF.Code)
	}
	retryJob := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, retryPath, retryBody, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if retryJob.Code != http.StatusNoContent {
		t.Fatalf("dead-job retry = status %d body %s", retryJob.Code, retryJob.Body.String())
	}
	staleRetry := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, retryPath, retryBody, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if staleRetry.Code != http.StatusConflict || !strings.Contains(staleRetry.Body.String(), `"dead_job_revision_conflict"`) {
		t.Fatalf("stale dead-job retry = status %d body %s", staleRetry.Code, staleRetry.Body.String())
	}
	recoveryID, err := queue.Enqueue(ctx, "synthetic-recovery-key", "expire-generic-uploads", `{"secret":"synthetic-hidden"}`, 3, jobNow, jobNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_jobs SET recovery_previous_status = 'pending', revision = 1 WHERE job_id = ?`, recoveryID); err != nil {
		t.Fatal(err)
	}
	listRecovery := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, "/api/v1/admin/jobs/recovery", "", authTestOrigin, "registry.example", mfaCookies, "")
	if listRecovery.Code != http.StatusOK || !strings.Contains(listRecovery.Body.String(), recoveryID) || strings.Contains(listRecovery.Body.String(), "synthetic-hidden") || strings.Contains(listRecovery.Body.String(), "synthetic-recovery-key") {
		t.Fatalf("recovery job list = status %d body %s", listRecovery.Code, listRecovery.Body.String())
	}
	releasePath := "/api/v1/admin/jobs/" + recoveryID + "/release-recovery"
	releaseBody := `{"expected_revision":1,"confirm_destinations_and_policies":true}`
	noMFARelease := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, releasePath, releaseBody, authTestOrigin, "registry.example", enrollmentCookies, enrollmentCookies[csrfCookieName].Value)
	if noMFARelease.Code == http.StatusNoContent {
		t.Fatal("recovery release accepted a session without recent MFA")
	}
	noReleaseCSRF := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, releasePath, releaseBody, authTestOrigin, "registry.example", mfaCookies, "")
	if noReleaseCSRF.Code != http.StatusForbidden {
		t.Fatalf("recovery release without CSRF = %d", noReleaseCSRF.Code)
	}
	noConfirmation := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, releasePath, `{"expected_revision":1,"confirm_destinations_and_policies":false}`, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if noConfirmation.Code != http.StatusPreconditionFailed {
		t.Fatalf("recovery release without confirmation = %d", noConfirmation.Code)
	}
	released := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, releasePath, releaseBody, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if released.Code != http.StatusNoContent {
		t.Fatalf("recovery release = status %d body %s", released.Code, released.Body.String())
	}
	staleRelease := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, releasePath, releaseBody, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if staleRelease.Code != http.StatusConflict || !strings.Contains(staleRelease.Body.String(), `"recovery_job_revision_conflict"`) {
		t.Fatalf("stale recovery release = status %d body %s", staleRelease.Code, staleRelease.Body.String())
	}

	payload := []byte("synthetic generic artifact")
	digest := sha256.Sum256(payload)
	startPath := fmt.Sprintf("/api/v1/workspaces/%s/repositories/%s/artifacts/uploads", workspace.ID, repository.ID)
	startBody := fmt.Sprintf(`{"collection":"widget","version":"2026.10","path":"dist/widget.js","content_type":"application/javascript","size":%d,"sha256":"%x"}`, len(payload), digest)
	quotaPath := fmt.Sprintf("/api/v1/admin/workspaces/%s/generic-logical-quota", workspace.ID)
	quotaGet := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, quotaPath, "", authTestOrigin, "registry.example", mfaCookies, "")
	if quotaGet.Code != http.StatusOK || !strings.Contains(quotaGet.Body.String(), `"mode":"unlimited"`) || !strings.Contains(quotaGet.Body.String(), `"revision":0`) {
		t.Fatalf("initial quota policy = status %d body %s", quotaGet.Code, quotaGet.Body.String())
	}
	quotaBody := fmt.Sprintf(`{"mode":"limited","limit_bytes":%d,"expected_revision":0}`, len(payload)-1)
	anonymous := authHTTPRequest(fixture.handler, http.MethodGet, quotaPath, "", authTestOrigin, "registry.example")
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous quota read = %d", anonymous.Code)
	}
	noCSRF := authHTTPRequestWithCookies(fixture.handler, http.MethodPut, quotaPath, quotaBody, authTestOrigin, "registry.example", mfaCookies, "")
	if noCSRF.Code != http.StatusForbidden {
		t.Fatalf("quota update without CSRF = %d", noCSRF.Code)
	}
	quotaSet := authHTTPRequestWithCookies(fixture.handler, http.MethodPut, quotaPath, quotaBody, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if quotaSet.Code != http.StatusOK || !strings.Contains(quotaSet.Body.String(), `"revision":1`) {
		t.Fatalf("set quota policy = status %d body %s", quotaSet.Code, quotaSet.Body.String())
	}
	nullLimit := authHTTPRequestWithCookies(fixture.handler, http.MethodPut, quotaPath, `{"mode":"unlimited","limit_bytes":null,"expected_revision":1}`, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if nullLimit.Code != http.StatusBadRequest {
		t.Fatalf("quota update with null optional value = %d", nullLimit.Code)
	}
	repositoryQuotaPath := fmt.Sprintf("/api/v1/admin/workspaces/%s/repositories/%s/generic-logical-quota", workspace.ID, repository.ID)
	repositoryQuotaBody := fmt.Sprintf(`{"mode":"limited","limit_bytes":%d,"expected_revision":0}`, len(payload))
	repositoryQuota := authHTTPRequestWithCookies(fixture.handler, http.MethodPut, repositoryQuotaPath, repositoryQuotaBody, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if repositoryQuota.Code != http.StatusOK || !strings.Contains(repositoryQuota.Body.String(), `"revision":1`) {
		t.Fatalf("set repository quota = status %d body %s", repositoryQuota.Code, repositoryQuota.Body.String())
	}
	quotaDenied := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, startPath, startBody,
		authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if quotaDenied.Code != http.StatusConflict || !strings.Contains(quotaDenied.Body.String(), `"logical_quota_exceeded"`) {
		t.Fatalf("quota rejection = status %d body %s", quotaDenied.Code, quotaDenied.Body.String())
	}
	stale := authHTTPRequestWithCookies(fixture.handler, http.MethodPut, quotaPath, quotaBody, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if stale.Code != http.StatusConflict || !strings.Contains(stale.Body.String(), `"logical_quota_revision_conflict"`) {
		t.Fatalf("stale quota update = status %d body %s", stale.Code, stale.Body.String())
	}
	quotaBody = fmt.Sprintf(`{"mode":"limited","limit_bytes":%d,"expected_revision":1}`, len(payload))
	quotaSet = authHTTPRequestWithCookies(fixture.handler, http.MethodPut, quotaPath, quotaBody, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if quotaSet.Code != http.StatusOK || !strings.Contains(quotaSet.Body.String(), `"revision":2`) {
		t.Fatalf("increase quota policy = status %d body %s", quotaSet.Code, quotaSet.Body.String())
	}
	start := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, startPath, startBody,
		authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if start.Code != http.StatusCreated {
		t.Fatalf("artifact upload session creation failed: status=%d body=%s", start.Code, start.Body.String())
	}
	var upload artifactUploadResponse
	if err := json.Unmarshal(start.Body.Bytes(), &upload); err != nil {
		t.Fatal("decode upload session response:", err)
	}
	if upload.UploadSessionID == "" || upload.ArtifactVersionID == "" || upload.Status != "receiving" {
		t.Fatalf("created upload session response is incomplete: %+v", upload)
	}
	usagePath := fmt.Sprintf("/api/v1/admin/workspaces/%s/generic-logical-usage", workspace.ID)
	usage := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, usagePath, "", authTestOrigin, "registry.example", mfaCookies, "")
	var usageData genericLogicalUsageResponse
	if usage.Code != http.StatusOK || json.Unmarshal(usage.Body.Bytes(), &usageData) != nil || usageData.ReservedBytes != int64(len(payload)) || usageData.PublishedBytes != 0 {
		t.Fatalf("reserved usage = status %d body %s", usage.Code, usage.Body.String())
	}

	contentPath := startPath + "/" + upload.UploadSessionID
	received := authRawHTTPRequestWithCookies(fixture.handler, http.MethodPut, contentPath, payload,
		"application/octet-stream", authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if received.Code != http.StatusOK || !strings.Contains(received.Body.String(), `"status":"uploaded"`) {
		t.Fatalf("artifact upload failed: status=%d body=%s", received.Code, received.Body.String())
	}

	publishPath := fmt.Sprintf("/api/v1/workspaces/%s/repositories/%s/artifacts/%s/publish",
		workspace.ID, repository.ID, upload.ArtifactVersionID)
	published := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, publishPath, "",
		authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if published.Code != http.StatusOK {
		t.Fatalf("artifact publication failed: status=%d body=%s", published.Code, published.Body.String())
	}
	usage = authHTTPRequestWithCookies(fixture.handler, http.MethodGet, usagePath, "", authTestOrigin, "registry.example", mfaCookies, "")
	if usage.Code != http.StatusOK || json.Unmarshal(usage.Body.Bytes(), &usageData) != nil || usageData.ReservedBytes != 0 || usageData.PublishedBytes != int64(len(payload)) {
		t.Fatalf("published usage = status %d body %s", usage.Code, usage.Body.String())
	}
	var version artifactVersionResponse
	if err := json.Unmarshal(published.Body.Bytes(), &version); err != nil {
		t.Fatal("decode published artifact:", err)
	}
	if version.Status != "published" || len(version.Files) != 1 || version.Files[0].SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("published artifact response = %+v; want one verified file", version)
	}
	publicPath := "/public/artifact-http/artifact-files/widget/2026.10/dist/widget.js"
	privatePublic := authAssetHTTPRequest(fixture.handler, http.MethodGet, publicPath, "assets.example", "")
	missingPublic := authAssetHTTPRequest(fixture.handler, http.MethodGet, "/public/artifact-http/artifact-files/widget/2026.10/dist/missing.js", "assets.example", "")
	if privatePublic.Code != http.StatusNotFound || missingPublic.Code != privatePublic.Code || missingPublic.Body.String() != privatePublic.Body.String() {
		t.Fatalf("private and missing public responses differ: private=%d/%s missing=%d/%s", privatePublic.Code, privatePublic.Body.String(), missingPublic.Code, missingPublic.Body.String())
	}
	privateCORS := authAssetCORSHTTPRequest(fixture.handler, http.MethodGet, publicPath, "https://consumer.example", "", "")
	if privateCORS.Code != http.StatusNotFound || privateCORS.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("private public CORS = status %d headers %v", privateCORS.Code, privateCORS.Header())
	}
	privatePreflight := authAssetCORSHTTPRequest(fixture.handler, http.MethodOptions, publicPath, "https://consumer.example", "GET", "")
	if privatePreflight.Code != http.StatusNotFound || privatePreflight.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("private public preflight = status %d headers %v", privatePreflight.Code, privatePreflight.Header())
	}
	if err := fixture.repositoryService.SetVisibilityPolicy(ctx, ownerID, repositories.PolicyAll); err != nil {
		t.Fatal("allow public visibility:", err)
	}
	if err := fixture.repositoryService.SetVisibility(ctx, ownerID, workspace.ID, repository.ID, repositories.VisibilityUnlisted, true); err != nil {
		t.Fatal("make repository unlisted:", err)
	}
	publicAsset := authAssetHTTPRequest(fixture.handler, http.MethodGet, publicPath, "assets.example", "")
	if publicAsset.Code != http.StatusOK || publicAsset.Body.String() != string(payload) || publicAsset.Header().Get("Cache-Control") != "no-store" || publicAsset.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(publicAsset.Header().Get("Content-Disposition"), "inline") || publicAsset.Header().Get("Content-Security-Policy") != "sandbox; default-src 'none'" || publicAsset.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("public asset = status %d headers %v body %q", publicAsset.Code, publicAsset.Header(), publicAsset.Body.String())
	}
	allowedCORS := authAssetCORSHTTPRequest(fixture.handler, http.MethodGet, publicPath, "https://consumer.example", "", "")
	if allowedCORS.Code != http.StatusOK || allowedCORS.Header().Get("Access-Control-Allow-Origin") != "https://consumer.example" || allowedCORS.Header().Get("Access-Control-Allow-Credentials") != "" || !strings.Contains(allowedCORS.Header().Get("Vary"), "Origin") {
		t.Fatalf("allowed public CORS = status %d headers %v", allowedCORS.Code, allowedCORS.Header())
	}
	deniedCORS := authAssetCORSHTTPRequest(fixture.handler, http.MethodGet, publicPath, "https://other.example", "", "")
	if deniedCORS.Code != http.StatusOK || deniedCORS.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unlisted public CORS = status %d headers %v", deniedCORS.Code, deniedCORS.Header())
	}
	preflight := authAssetCORSHTTPRequest(fixture.handler, http.MethodOptions, publicPath, "https://consumer.example", "GET", "range, if-none-match")
	if preflight.Code != http.StatusNoContent || preflight.Header().Get("Access-Control-Allow-Origin") != "https://consumer.example" || preflight.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("public preflight = status %d headers %v", preflight.Code, preflight.Header())
	}
	unsafePreflight := authAssetCORSHTTPRequest(fixture.handler, http.MethodOptions, publicPath, "https://consumer.example", "GET", "authorization")
	if unsafePreflight.Code != http.StatusForbidden || unsafePreflight.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unsafe public preflight = status %d headers %v", unsafePreflight.Code, unsafePreflight.Header())
	}
	deniedPreflight := authAssetCORSHTTPRequest(fixture.handler, http.MethodOptions, publicPath, "https://other.example", "GET", "")
	if deniedPreflight.Code != http.StatusForbidden || deniedPreflight.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unlisted public preflight = status %d headers %v", deniedPreflight.Code, deniedPreflight.Header())
	}
	publicRange := authAssetHTTPRequest(fixture.handler, http.MethodGet, publicPath, "assets.example", "bytes=4-9")
	if publicRange.Code != http.StatusPartialContent || publicRange.Body.String() != string(payload[4:10]) {
		t.Fatalf("public range = status %d body %q", publicRange.Code, publicRange.Body.String())
	}
	invalidPublicRange := authAssetHTTPRequest(fixture.handler, http.MethodGet, publicPath, "assets.example", "bytes=999-")
	if invalidPublicRange.Code != http.StatusRequestedRangeNotSatisfiable || invalidPublicRange.Header().Get("Content-Length") != "" {
		t.Fatalf("invalid public range = status %d length %q", invalidPublicRange.Code, invalidPublicRange.Header().Get("Content-Length"))
	}
	publicNotModified := authAssetConditionalHTTPRequest(fixture.handler, http.MethodGet, publicPath, "assets.example", "", publicAsset.Header().Get("ETag"), "")
	if publicNotModified.Code != http.StatusNotModified || publicNotModified.Body.Len() != 0 {
		t.Fatalf("conditional public asset = status %d body %q", publicNotModified.Code, publicNotModified.Body.String())
	}
	publicHead := authAssetHTTPRequest(fixture.handler, http.MethodHead, publicPath, "assets.example", "")
	if publicHead.Code != http.StatusOK || publicHead.Body.Len() != 0 || publicHead.Header().Get("Content-Length") != fmt.Sprint(len(payload)) {
		t.Fatalf("public HEAD = status %d length %s", publicHead.Code, publicHead.Header().Get("Content-Length"))
	}
	if wrongOrigin := authAssetHTTPRequest(fixture.handler, http.MethodGet, publicPath, "registry.example", ""); wrongOrigin.Code != http.StatusForbidden {
		t.Fatalf("public asset on administrative origin = %d", wrongOrigin.Code)
	}
	if err := fixture.repositoryService.SetVisibility(ctx, ownerID, workspace.ID, repository.ID, repositories.VisibilityListed, true); err != nil {
		t.Fatal("make repository listed:", err)
	}
	if listed := authAssetHTTPRequest(fixture.handler, http.MethodGet, publicPath, "assets.example", ""); listed.Code != http.StatusOK {
		t.Fatalf("listed public asset = %d", listed.Code)
	}
	if err := fixture.repositoryService.SetVisibility(ctx, ownerID, workspace.ID, repository.ID, repositories.VisibilityPrivate, false); err != nil {
		t.Fatal("make repository private again:", err)
	}
	if privateAgain := authAssetConditionalHTTPRequest(fixture.handler, http.MethodGet, publicPath, "assets.example", "", publicAsset.Header().Get("ETag"), ""); privateAgain.Code != http.StatusNotFound {
		t.Fatalf("conditional public request after privatization = %d", privateAgain.Code)
	}
	tokenIssuePath := fmt.Sprintf("/api/v1/workspaces/%s/repositories/%s/personal-read-tokens", workspace.ID, repository.ID)
	if denied := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, cargoIssuePath, `{}`, authTestOrigin, "registry.example", mfaCookies, ""); denied.Code != http.StatusForbidden {
		t.Fatalf("Cargo credential issuance without CSRF: %d", denied.Code)
	}
	cargoIssue := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, cargoIssuePath, `{}`, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	var cargoCredential issuedPersonalTokenResponse
	if cargoIssue.Code != http.StatusCreated || json.Unmarshal(cargoIssue.Body.Bytes(), &cargoCredential) != nil || cargoCredential.Bearer == "" || cargoCredential.Token.TokenID == "" || cargoIssue.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cargo credential issuance failed: status=%d", cargoIssue.Code)
	}
	cargoList := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, "/api/v1/cargo-write-tokens", "", authTestOrigin, "registry.example", mfaCookies, "")
	var cargoTokens personalTokenListResponse
	if cargoList.Code != http.StatusOK || json.Unmarshal(cargoList.Body.Bytes(), &cargoTokens) != nil || len(cargoTokens.Tokens) != 1 || cargoTokens.Tokens[0].TokenID != cargoCredential.Token.TokenID || strings.Contains(cargoList.Body.String(), cargoCredential.Bearer) {
		t.Fatalf("Cargo credential metadata listing failed: status=%d", cargoList.Code)
	}
	cargoRevoke := "/api/v1/cargo-write-tokens/" + cargoCredential.Token.TokenID
	if denied := authHTTPRequestWithCookies(fixture.handler, http.MethodDelete, cargoRevoke, "", authTestOrigin, "registry.example", mfaCookies, ""); denied.Code != http.StatusForbidden {
		t.Fatalf("Cargo credential revocation without CSRF: %d", denied.Code)
	}
	if revoked := authHTTPRequestWithCookies(fixture.handler, http.MethodDelete, cargoRevoke, "", authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value); revoked.Code != http.StatusNoContent {
		t.Fatalf("Cargo credential revocation failed: %d", revoked.Code)
	}
	if err := fixture.repositoryService.WithCargoWriteTokenTransaction(ctx, cargoCredential.Bearer, workspace.ID, cargoRepository, func(_ *sql.Tx, _ string) error { return nil }); !errors.Is(err, repositories.ErrCargoWriteTokenUnavailable) {
		t.Fatalf("revoked Cargo credential remained valid: %v", err)
	}
	if err := fixture.repositoryService.RevokeRepositoryRole(ctx, ownerID, workspace.ID, cargoRepository, ownerID, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if denied := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, cargoIssuePath, `{}`, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value); denied.Code == http.StatusCreated {
		t.Fatal("Cargo credential issued after publisher grant revocation")
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, ownerID, workspace.ID, cargoRepository, ownerID, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	cargoStaleMFA := time.Now().UTC().Add(-workspaceCreationMFAMaxAge - time.Minute).Format(time.RFC3339Nano)
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_auth_sessions SET mfa_verified_at = ? WHERE user_id = ? AND level = 'mfa' AND revoked_at IS NULL`, cargoStaleMFA, ownerID); err != nil {
		t.Fatal(err)
	}
	if denied := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, cargoIssuePath, `{}`, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value); denied.Code != http.StatusForbidden {
		t.Fatalf("Cargo credential issuance with stale MFA: %d", denied.Code)
	}
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_auth_sessions SET mfa_verified_at = ? WHERE user_id = ? AND level = 'mfa' AND revoked_at IS NULL`, time.Now().UTC().Format(time.RFC3339Nano), ownerID); err != nil {
		t.Fatal(err)
	}
	withoutTokenCSRF := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, tokenIssuePath, `{}`, authTestOrigin, "registry.example", mfaCookies, "")
	if withoutTokenCSRF.Code != http.StatusForbidden {
		t.Fatalf("token issuance without CSRF = %d", withoutTokenCSRF.Code)
	}
	issueResponse := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, tokenIssuePath, `{}`, authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	var personal issuedPersonalTokenResponse
	if issueResponse.Code != http.StatusCreated || json.Unmarshal(issueResponse.Body.Bytes(), &personal) != nil || personal.Token.TokenID == "" || personal.Bearer == "" || issueResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("personal token issuance failed: status=%d", issueResponse.Code)
	}
	listTokens := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, "/api/v1/personal-read-tokens", "", authTestOrigin, "registry.example", mfaCookies, "")
	var tokenList personalTokenListResponse
	if listTokens.Code != http.StatusOK || json.Unmarshal(listTokens.Body.Bytes(), &tokenList) != nil || len(tokenList.Tokens) != 1 || tokenList.Tokens[0].TokenID != personal.Token.TokenID || strings.Contains(listTokens.Body.String(), personal.Bearer) {
		t.Fatalf("personal token metadata listing failed: status=%d", listTokens.Code)
	}
	tokenManifestPath := fmt.Sprintf("/api/v1/token/workspaces/%s/repositories/%s/artifacts/%s", workspace.ID, repository.ID, version.ArtifactVersionID)
	tokenManifest := authBearerHTTPRequest(fixture.handler, http.MethodGet, tokenManifestPath, "registry.example", "bearer "+personal.Bearer, "", "")
	if tokenManifest.Code != http.StatusOK {
		t.Fatalf("token manifest status=%d", tokenManifest.Code)
	}
	filePath := fmt.Sprintf("/api/v1/token/workspaces/%s/repositories/%s/files/%s", workspace.ID, repository.ID, version.Files[0].ArtifactFileID)
	tokenFile := authBearerHTTPRequest(fixture.handler, http.MethodGet, filePath, "assets.example", "Bearer "+personal.Bearer, "bytes=4-9", "https://consumer.example")
	if tokenFile.Code != http.StatusPartialContent || tokenFile.Body.String() != string(payload[4:10]) || tokenFile.Header().Get("Cache-Control") != "private, no-store" || tokenFile.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("token file status=%d headers=%v", tokenFile.Code, tokenFile.Header())
	}
	wrongTokenHost := authBearerHTTPRequest(fixture.handler, http.MethodGet, filePath, "registry.example", "Bearer "+personal.Bearer, "", "")
	if wrongTokenHost.Code != http.StatusForbidden {
		t.Fatalf("token content on administrative origin = %d", wrongTokenHost.Code)
	}
	wrongRepository := fmt.Sprintf("/api/v1/token/workspaces/%s/repositories/%s/artifacts/%s", workspace.ID, uuid.NewString(), version.ArtifactVersionID)
	if denied := authBearerHTTPRequest(fixture.handler, http.MethodGet, wrongRepository, "registry.example", "Bearer "+personal.Bearer, "", ""); denied.Code != http.StatusUnauthorized {
		t.Fatalf("cross-repository token request = %d", denied.Code)
	}
	revokePath := "/api/v1/personal-read-tokens/" + personal.Token.TokenID
	if denied := authHTTPRequestWithCookies(fixture.handler, http.MethodDelete, revokePath, "", authTestOrigin, "registry.example", mfaCookies, ""); denied.Code != http.StatusForbidden {
		t.Fatalf("token revocation without CSRF = %d", denied.Code)
	}
	revokedToken := authHTTPRequestWithCookies(fixture.handler, http.MethodDelete, revokePath, "", authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if revokedToken.Code != http.StatusNoContent {
		t.Fatalf("token revocation = %d", revokedToken.Code)
	}
	if denied := authBearerHTTPRequest(fixture.handler, http.MethodGet, filePath, "assets.example", "Bearer "+personal.Bearer, "", ""); denied.Code != http.StatusUnauthorized {
		t.Fatalf("revoked bearer request = %d", denied.Code)
	}
	manifestPath := fmt.Sprintf("/api/v1/workspaces/%s/repositories/%s/artifacts/%s",
		workspace.ID, repository.ID, version.ArtifactVersionID)
	manifest := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, manifestPath, "",
		authTestOrigin, "registry.example", mfaCookies, "")
	if manifest.Code != http.StatusOK {
		t.Fatalf("published artifact manifest query failed: status=%d body=%s", manifest.Code, manifest.Body.String())
	}
	var queriedManifest artifactVersionResponse
	if err := json.Unmarshal(manifest.Body.Bytes(), &queriedManifest); err != nil {
		t.Fatal("decode queried artifact manifest:", err)
	}
	if queriedManifest.ArtifactVersionID != version.ArtifactVersionID || len(queriedManifest.Files) != 1 {
		t.Fatalf("queried manifest = %+v; want published version %+v", queriedManifest, version)
	}

	linkPath := fmt.Sprintf("/api/v1/workspaces/%s/repositories/%s/artifacts/%s/files/%s/download-link",
		workspace.ID, repository.ID, version.ArtifactVersionID, version.Files[0].ArtifactFileID)
	linkResponse := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, linkPath, `{}`,
		authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if linkResponse.Code != http.StatusCreated {
		t.Fatalf("authorized download link creation failed: status=%d body=%s", linkResponse.Code, linkResponse.Body.String())
	}
	var downloadLink artifactDownloadLinkResponse
	if err := json.Unmarshal(linkResponse.Body.Bytes(), &downloadLink); err != nil {
		t.Fatal("decode download link response:", err)
	}
	if !strings.HasPrefix(downloadLink.DownloadURL, authTestAssetOrigin+"/api/v1/assets/") ||
		downloadLink.File.ArtifactFileID != version.Files[0].ArtifactFileID || downloadLink.ExpiresAt == "" {
		t.Fatalf("download link response is invalid: %+v", downloadLink)
	}
	assetPath := strings.TrimPrefix(downloadLink.DownloadURL, authTestAssetOrigin)
	assetDownload := authAssetHTTPRequest(fixture.handler, http.MethodGet, assetPath, "assets.example", "")
	if assetDownload.Code != http.StatusOK || assetDownload.Body.String() != string(payload) {
		t.Fatalf("asset-origin download failed: status=%d body=%q", assetDownload.Code, assetDownload.Body.String())
	}
	privateTicketCORS := authAssetCORSHTTPRequest(fixture.handler, http.MethodGet, assetPath, "https://consumer.example", "", "")
	if privateTicketCORS.Code != http.StatusOK || privateTicketCORS.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("private ticket CORS = status %d headers %v", privateTicketCORS.Code, privateTicketCORS.Header())
	}
	if assetDownload.Header().Get("Content-Disposition") == "" ||
		!strings.HasPrefix(assetDownload.Header().Get("Content-Disposition"), "attachment") ||
		assetDownload.Header().Get("X-Content-Type-Options") != "nosniff" ||
		assetDownload.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("unsafe asset response headers: %v", assetDownload.Header())
	}
	etag := assetDownload.Header().Get("ETag")
	conditionalAsset := authAssetConditionalHTTPRequest(fixture.handler, http.MethodGet, assetPath,
		"assets.example", "", etag, "")
	if conditionalAsset.Code != http.StatusNotModified || conditionalAsset.Body.Len() != 0 {
		t.Fatalf("conditional asset request status=%d body=%q; want empty 304", conditionalAsset.Code, conditionalAsset.Body.String())
	}
	rangedAsset := authAssetHTTPRequest(fixture.handler, http.MethodGet, assetPath, "assets.example", "bytes=4-9")
	if rangedAsset.Code != http.StatusPartialContent || rangedAsset.Body.String() != string(payload[4:10]) ||
		rangedAsset.Header().Get("Content-Range") != fmt.Sprintf("bytes 4-9/%d", len(payload)) {
		t.Fatalf("asset range failed: status=%d range=%q body=%q", rangedAsset.Code,
			rangedAsset.Header().Get("Content-Range"), rangedAsset.Body.String())
	}
	ignoredRange := authAssetConditionalHTTPRequest(fixture.handler, http.MethodGet, assetPath,
		"assets.example", "bytes=4-9", "", `"stale-etag"`)
	if ignoredRange.Code != http.StatusOK || ignoredRange.Body.String() != string(payload) {
		t.Fatalf("If-Range mismatch response status=%d body=%q; want full 200 response", ignoredRange.Code, ignoredRange.Body.String())
	}
	unsatisfiedRange := authAssetHTTPRequest(fixture.handler, http.MethodGet, assetPath, "assets.example", "bytes=99-")
	if unsatisfiedRange.Code != http.StatusRequestedRangeNotSatisfiable ||
		unsatisfiedRange.Header().Get("Content-Range") != fmt.Sprintf("bytes */%d", len(payload)) {
		t.Fatalf("unsatisfied asset range status=%d content-range=%q", unsatisfiedRange.Code, unsatisfiedRange.Header().Get("Content-Range"))
	}
	assetHead := authAssetHTTPRequest(fixture.handler, http.MethodHead, assetPath, "assets.example", "")
	if assetHead.Code != http.StatusOK || assetHead.Body.Len() != 0 ||
		assetHead.Header().Get("Content-Length") != fmt.Sprint(len(payload)) {
		t.Fatalf("asset HEAD failed: status=%d content-length=%q body=%q", assetHead.Code,
			assetHead.Header().Get("Content-Length"), assetHead.Body.String())
	}
	wrongAssetOrigin := authAssetHTTPRequest(fixture.handler, http.MethodGet, assetPath, "registry.example", "")
	if wrongAssetOrigin.Code != http.StatusForbidden {
		t.Fatalf("asset ticket was served from administrative origin: status=%d body=%s", wrongAssetOrigin.Code, wrongAssetOrigin.Body.String())
	}

	if err := fixture.repositoryService.RevokeRepositoryRole(ctx, ownerID, workspace.ID, repository.ID,
		ownerID, repositories.GrantPublisher); err != nil {
		t.Fatal("revoke explicit publisher grant:", err)
	}
	retry := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, publishPath, "",
		authTestOrigin, "registry.example", mfaCookies, mfaCookies[csrfCookieName].Value)
	if retry.Code != http.StatusForbidden {
		t.Fatalf("publication retry after grant revocation status=%d body=%s; want 403", retry.Code, retry.Body.String())
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

func authRawHTTPRequestWithCookies(
	handler http.Handler,
	method string,
	path string,
	body []byte,
	contentType string,
	origin string,
	host string,
	cookies map[string]*http.Cookie,
	csrfHeader string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://registry.example"+path, bytes.NewReader(body))
	request.Header.Set("Content-Type", contentType)
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

func authBearerHTTPRequest(handler http.Handler, method, path, host, authorization, rangeHeader, origin string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://"+host+path, nil)
	request.Host = host
	request.TLS = &tls.ConnectionState{}
	request.RemoteAddr = "192.0.2.10:54321"
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if rangeHeader != "" {
		request.Header.Set("Range", rangeHeader)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func authAssetCORSHTTPRequest(handler http.Handler, method, path, origin, requestedMethod, requestedHeaders string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://assets.example"+path, nil)
	request.Host = "assets.example"
	request.TLS = &tls.ConnectionState{}
	request.RemoteAddr = "192.0.2.10:54321"
	request.Header.Set("Origin", origin)
	if requestedMethod != "" {
		request.Header.Set("Access-Control-Request-Method", requestedMethod)
	}
	if requestedHeaders != "" {
		request.Header.Set("Access-Control-Request-Headers", requestedHeaders)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func authAssetHTTPRequest(
	handler http.Handler,
	method string,
	path string,
	host string,
	rangeHeader string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://assets.example"+path, nil)
	request.Host = host
	request.TLS = &tls.ConnectionState{}
	request.RemoteAddr = "192.0.2.10:54321"
	if rangeHeader != "" {
		request.Header.Set("Range", rangeHeader)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func authAssetConditionalHTTPRequest(
	handler http.Handler,
	method string,
	path string,
	host string,
	rangeHeader string,
	ifNoneMatch string,
	ifRange string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://assets.example"+path, nil)
	request.Host = host
	request.TLS = &tls.ConnectionState{}
	request.RemoteAddr = "192.0.2.10:54321"
	if rangeHeader != "" {
		request.Header.Set("Range", rangeHeader)
	}
	if ifNoneMatch != "" {
		request.Header.Set("If-None-Match", ifNoneMatch)
	}
	if ifRange != "" {
		request.Header.Set("If-Range", ifRange)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func seedHTTPUser(t *testing.T, fixture authHTTPFixture, loginName string) string {
	t.Helper()
	userID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	passwordValue := []byte("synthetic-http-member-password")
	passwordHash, err := password.Hash(passwordValue)
	clear(passwordValue)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := fixture.db.Exec(`INSERT INTO registry_users
		(user_id, display_name, email, email_verified, status, created_at, updated_at)
		VALUES (?, ?, NULL, 0, 'active', ?, ?)`, userID.String(), "Synthetic HTTP Member", now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.Exec(`INSERT INTO registry_local_credentials
		(user_id, login_name, password_hash, created_at, updated_at, password_changed_at)
		VALUES (?, ?, ?, ?, ?, ?)`, userID.String(), loginName, passwordHash, now, now, now); err != nil {
		t.Fatal(err)
	}
	return userID.String()
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
