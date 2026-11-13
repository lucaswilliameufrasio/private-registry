package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/gomod"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
)

func TestGoManagementReviewedPublicationOverTLS(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var owner string
	if err := fixture.db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	reviewer := seedHTTPUser(t, fixture, "go.reviewer")
	standardPublisher := seedHTTPUser(t, fixture, "go.standard")
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "go-management", "Go management")
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.workspaceService.SetMembershipRole(ctx, owner, workspace.ID, reviewer, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := fixture.workspaceService.SetMembershipRole(ctx, owner, workspace.ID, standardPublisher, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	repo, err := fixture.repositoryService.CreateWithFormat(ctx, owner, workspace.ID, "modules", "Modules", repositories.FormatGo)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []repositories.GrantRole{repositories.GrantPublisher, repositories.GrantReader} {
		if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repo.ID, owner, role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repo.ID, standardPublisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	standardLogin := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login", `{"login_name":"go.standard","password":"synthetic-http-member-password"}`, authTestOrigin, "registry.example")
	if standardLogin.Code != http.StatusOK {
		t.Fatalf("standard publisher login status=%d", standardLogin.Code)
	}
	standardCookies := assertSessionCookies(t, standardLogin)
	enroll := func(login, password, startPath string) map[string]*http.Cookie {
		t.Helper()
		loginResult := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login", fmt.Sprintf(`{"login_name":%q,"password":%q}`, login, password), authTestOrigin, "registry.example")
		if loginResult.Code != http.StatusOK {
			t.Fatalf("synthetic login status=%d", loginResult.Code)
		}
		cookies := assertSessionCookies(t, loginResult)
		start := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, startPath, "", authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value)
		if start.Code != http.StatusOK {
			t.Fatalf("synthetic MFA enrollment status=%d", start.Code)
		}
		var enrollment enrollmentResponse
		if err := json.Unmarshal(start.Body.Bytes(), &enrollment); err != nil {
			t.Fatal(err)
		}
		if startPath == "/api/v1/auth/mfa/enrollment/start" {
			cookies = assertSessionCookies(t, start)
		}
		secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(secret)
		complete := authHTTPRequestWithCookies(fixture.handler, http.MethodPost, "/api/v1/auth/mfa/enrollment/complete", fmt.Sprintf(`{"code":%q}`, authHTTPOTP(secret, time.Now().Unix()/30)), authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value)
		if complete.Code != http.StatusOK {
			t.Fatalf("synthetic MFA completion status=%d", complete.Code)
		}
		return assertSessionCookies(t, complete)
	}
	ownerCookies := enroll(authTestLogin, authTestPassword, "/api/v1/auth/mfa/enrollment")
	reviewerCookies := enroll("go.reviewer", "synthetic-http-member-password", "/api/v1/auth/mfa/enrollment/start")
	root := t.TempDir()
	objectStore, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	modules, err := gomod.NewService(fixture.db, config.SQLite, fixture.repositoryService, objectStore, gomod.Options{StagingDirectory: staging, MaxZipBytes: 1 << 20, MaxFiles: 100, MaxConcurrent: 2})
	if err != nil {
		t.Fatal(err)
	}
	var handler http.Handler
	var checksumLookups atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/unused-sumdb") {
			checksumLookups.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	handler, err = NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: server.URL, AssetOrigin: "https://assets.example", GoModules: modules})
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	call := func(method, path, contentType string, body []byte, cookies map[string]*http.Cookie, csrf bool) (int, []byte) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", server.URL)
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		if csrf {
			request.Header.Set(csrfHeaderName, cookies[csrfCookieName].Value)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read synthetic response: %v %v", readErr, closeErr)
		}
		return response.StatusCode, data
	}
	base := "/api/v1/workspaces/" + workspace.ID + "/repositories/" + repo.ID + "/go"
	if status, _ := call(http.MethodPut, base+"/namespace-policy", "application/json", []byte(`{"mode":"private_prefixes","private_prefixes":["example.com/private"],"expected_revision":0}`), ownerCookies, true); status != http.StatusPreconditionFailed {
		t.Fatalf("public fallback enabled without confirmation: %d", status)
	}
	if status, body := call(http.MethodPut, base+"/namespace-policy", "application/json", []byte(`{"mode":"private_prefixes","private_prefixes":["example.com/private"],"expected_revision":0,"confirm_public_fallback":true}`), ownerCookies, true); status != http.StatusOK {
		t.Fatalf("confirmed namespace policy status=%d body=%s", status, body)
	}
	if status, _ := call(http.MethodPut, base+"/review-policy", "application/json", []byte(`{"required":true,"expected_revision":0}`), ownerCookies, false); status != http.StatusForbidden {
		t.Fatalf("review policy accepted missing CSRF: %d", status)
	}
	if status, body := call(http.MethodPut, base+"/review-policy", "application/json", []byte(`{"required":true,"expected_revision":0}`), ownerCookies, true); status != http.StatusOK {
		t.Fatalf("set review policy status=%d body=%s", status, body)
	}
	if status, body := call(http.MethodPut, base+"/reviewers/"+reviewer, "", nil, ownerCookies, true); status != http.StatusOK {
		t.Fatalf("grant reviewer status=%d body=%s", status, body)
	}
	if status, body := call(http.MethodPut, base+"/reviewers/"+owner, "", nil, ownerCookies, true); status != http.StatusOK {
		t.Fatalf("grant owner reviewer status=%d body=%s", status, body)
	}
	if status, body := call(http.MethodPut, base+"/reviewers/"+standardPublisher, "", nil, ownerCookies, true); status != http.StatusOK {
		t.Fatalf("grant standard reviewer status=%d body=%s", status, body)
	}
	modulePath, version := "example.com/private/managed", "v1.0.0"
	mod := "module " + modulePath + "\n\ngo 1.24\n"
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for name, content := range map[string]string{"go.mod": mod, "module.go": "package managed\n"} {
		entry, err := writer.Create(modulePath + "@" + version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archive.Bytes())
	requestBody, err := json.Marshal(map[string]any{"module_path": modulePath, "version": version, "source_time": time.Now().UTC().Format(time.RFC3339Nano), "go_mod": mod, "zip_size": archive.Len(), "zip_sha256": hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	outsideBody, err := json.Marshal(map[string]any{"module_path": "example.net/public", "version": version, "source_time": time.Now().UTC().Format(time.RFC3339Nano), "go_mod": "module example.net/public\n", "zip_size": archive.Len(), "zip_sha256": hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatal(err)
	}
	if status, body := call(http.MethodPost, base+"/uploads", "application/json", outsideBody, ownerCookies, true); status != http.StatusConflict || !bytes.Contains(body, []byte(`"private_namespace_required"`)) {
		t.Fatalf("outside-namespace reservation status=%d body=%s", status, body)
	}
	if status, _ := call(http.MethodPost, base+"/uploads", "application/json", requestBody, standardCookies, true); status != http.StatusForbidden {
		t.Fatalf("standard session reserved a Go upload without MFA: %d", status)
	}
	status, body := call(http.MethodPost, base+"/uploads", "application/json", requestBody, ownerCookies, true)
	var reservation struct {
		ID string `json:"upload_session_id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &reservation) != nil || reservation.ID == "" {
		t.Fatalf("reserve Go upload status=%d body=%s", status, body)
	}
	status, body = call(http.MethodPost, base+"/uploads", "application/json", requestBody, ownerCookies, true)
	var retry struct {
		ID string `json:"upload_session_id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &retry) != nil || retry.ID != reservation.ID {
		t.Fatalf("repeat Go reservation status=%d body=%s", status, body)
	}
	if status, _ := call(http.MethodPut, base+"/uploads/"+reservation.ID+"/content", "application/octet-stream", []byte("invalid"), ownerCookies, true); status != http.StatusBadRequest {
		t.Fatalf("invalid Go upload was not rejected: %d", status)
	}
	if status, body := call(http.MethodPut, base+"/uploads/"+reservation.ID+"/content", "application/octet-stream", archive.Bytes(), ownerCookies, true); status != http.StatusNoContent {
		t.Fatalf("receive Go upload status=%d body=%s", status, body)
	}
	if status, body := call(http.MethodGet, base+"/uploads/"+reservation.ID, "", nil, ownerCookies, false); status != http.StatusOK || !bytes.Contains(body, []byte(`"status":"uploaded"`)) || !bytes.Contains(body, []byte(`"review_state":"awaiting_review"`)) {
		t.Fatalf("Go upload status=%d body=%s", status, body)
	}
	issued, err := fixture.repositoryService.IssuePersonalReadToken(ctx, owner, workspace.ID, repo.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pendingRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/go/"+workspace.ID+"/"+repo.ID+"/"+modulePath+"/@v/"+version+".zip", nil)
	if err != nil {
		t.Fatal(err)
	}
	pendingRequest.Header.Set("Authorization", "Bearer "+issued.Bearer)
	pendingResponse, err := client.Do(pendingRequest)
	if err != nil {
		t.Fatal(err)
	}
	_, pendingReadErr := io.Copy(io.Discard, pendingResponse.Body)
	pendingCloseErr := pendingResponse.Body.Close()
	if pendingReadErr != nil || pendingCloseErr != nil || pendingResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("unapproved Go module proxy status=%d read=%v close=%v", pendingResponse.StatusCode, pendingReadErr, pendingCloseErr)
	}
	if status, _ := call(http.MethodPost, base+"/uploads/"+reservation.ID+"/publish", "", nil, ownerCookies, true); status != http.StatusConflict {
		t.Fatalf("Go upload published before review: %d", status)
	}
	if status, body := call(http.MethodGet, base+"/reviews", "", nil, reviewerCookies, false); status != http.StatusOK || !bytes.Contains(body, []byte(reservation.ID)) {
		t.Fatalf("review list status=%d body=%s", status, body)
	}
	if status, body := call(http.MethodGet, base+"/reviews/"+reservation.ID+"/mod", "", nil, reviewerCookies, false); status != http.StatusOK || string(body) != mod {
		t.Fatalf("review go.mod status=%d", status)
	}
	if status, body := call(http.MethodGet, base+"/reviews/"+reservation.ID+"/zip", "", nil, reviewerCookies, false); status != http.StatusOK || !bytes.Equal(body, archive.Bytes()) {
		t.Fatalf("review ZIP status=%d", status)
	}
	if status, _ := call(http.MethodPost, base+"/reviews/"+reservation.ID+"/approve", "", nil, ownerCookies, true); status != http.StatusForbidden {
		t.Fatalf("publisher self-approval returned %d", status)
	}
	if status, _ := call(http.MethodPost, base+"/reviews/"+reservation.ID+"/approve", "", nil, standardCookies, true); status != http.StatusForbidden {
		t.Fatalf("reviewer approved without recent MFA: %d", status)
	}
	if status, body := call(http.MethodPost, base+"/reviews/"+reservation.ID+"/approve", "", nil, reviewerCookies, true); status != http.StatusNoContent {
		t.Fatalf("approve Go upload status=%d body=%s", status, body)
	}
	if status, body := call(http.MethodGet, base+"/uploads/"+reservation.ID, "", nil, ownerCookies, false); status != http.StatusOK || !bytes.Contains(body, []byte(`"review_state":"approved"`)) {
		t.Fatalf("approved review status=%d body=%s", status, body)
	}
	if status, body := call(http.MethodDelete, base+"/reviewers/"+reviewer, "", nil, ownerCookies, true); status != http.StatusNoContent {
		t.Fatalf("revoke reviewer status=%d body=%s", status, body)
	}
	if status, body := call(http.MethodGet, base+"/uploads/"+reservation.ID, "", nil, ownerCookies, false); status != http.StatusOK || !bytes.Contains(body, []byte(`"review_state":"awaiting_review"`)) {
		t.Fatalf("revoked review state status=%d body=%s", status, body)
	}
	if status, _ := call(http.MethodGet, base+"/reviews/"+reservation.ID+"/mod", "", nil, reviewerCookies, false); status != http.StatusForbidden {
		t.Fatalf("revoked reviewer could inspect pending content: %d", status)
	}
	if status, _ := call(http.MethodPost, base+"/uploads/"+reservation.ID+"/publish", "", nil, ownerCookies, true); status != http.StatusConflict {
		t.Fatalf("revoked reviewer approval allowed publication: %d", status)
	}
	if status, body := call(http.MethodPut, base+"/reviewers/"+reviewer, "", nil, ownerCookies, true); status != http.StatusOK {
		t.Fatalf("regrant reviewer status=%d body=%s", status, body)
	}
	if status, _ := call(http.MethodPost, base+"/uploads/"+reservation.ID+"/publish", "", nil, ownerCookies, true); status != http.StatusConflict {
		t.Fatalf("regrant revived the old review: %d", status)
	}
	if status, body := call(http.MethodPost, base+"/reviews/"+reservation.ID+"/approve", "", nil, reviewerCookies, true); status != http.StatusNoContent {
		t.Fatalf("renew review status=%d body=%s", status, body)
	}
	for range 2 {
		if status, body := call(http.MethodPost, base+"/uploads/"+reservation.ID+"/publish", "", nil, ownerCookies, true); status != http.StatusNoContent {
			t.Fatalf("publish Go upload or retry status=%d body=%s", status, body)
		}
	}
	if status, body := call(http.MethodGet, base+"/uploads/"+reservation.ID, "", nil, ownerCookies, false); status != http.StatusOK || !bytes.Contains(body, []byte(`"review_state":"completed"`)) {
		t.Fatalf("completed review state status=%d body=%s", status, body)
	}
	proxyRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/go/"+workspace.ID+"/"+repo.ID+"/"+modulePath+"/@v/"+version+".zip", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyRequest.Header.Set("Authorization", "Bearer "+issued.Bearer)
	proxyResponse, err := client.Do(proxyRequest)
	if err != nil {
		t.Fatal(err)
	}
	proxyBytes, readErr := io.ReadAll(proxyResponse.Body)
	closeErr := proxyResponse.Body.Close()
	if readErr != nil || closeErr != nil || proxyResponse.StatusCode != http.StatusOK || !bytes.Equal(proxyBytes, archive.Bytes()) {
		t.Fatalf("published Go proxy status=%d read=%v close=%v", proxyResponse.StatusCode, readErr, closeErr)
	}
	caPath := filepath.Join(root, "fixture-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(root, "goauth.sh")
	if err := os.WriteFile(authPath, []byte("#!/bin/sh\nprintf '%s\\n\\nAuthorization: Bearer %s\\n\\n' \"$SYNTHETIC_GO_URL\" \"$SYNTHETIC_GO_TOKEN\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	clientDir := filepath.Join(root, "client")
	if err := os.Mkdir(clientDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clientDir, "go.mod"), []byte("module example.com/synthetic-client\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "mod", "download", "-json", modulePath+"@"+version)
	command.Dir = clientDir
	command.Env = []string{
		"PATH=/usr/bin:/bin", "HOME=" + root, "GOROOT=" + runtime.GOROOT(), "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=-modcacherw",
		"GOCACHE=" + filepath.Join(root, "cache"), "GOMODCACHE=" + filepath.Join(root, "modules"),
		"GOPROXY=" + server.URL + "/go/" + workspace.ID + "/" + repo.ID, "GOPRIVATE=example.com/private", "GONOPROXY=none", "GONOSUMDB=example.com/private",
		"GOSUMDB=sum.golang.org " + server.URL + "/unused-sumdb", "GOAUTH=/bin/sh " + authPath, "SSL_CERT_FILE=" + caPath,
		"SYNTHETIC_GO_URL=" + server.URL, "SYNTHETIC_GO_TOKEN=" + issued.Bearer,
	}
	output, err := command.Output()
	if err != nil || !bytes.Contains(output, []byte(`"Version": "v1.0.0"`)) {
		t.Fatalf("real Go client could not consume API-published version: %v", err)
	}
	if checksumLookups.Load() != 0 {
		t.Fatalf("private Go dependency contacted checksum fixture %d times", checksumLookups.Load())
	}
	if strings.Contains(string(body), issued.Bearer) {
		t.Fatal("API response exposed a personal bearer token")
	}
	oversizedBody, err := json.Marshal(map[string]any{"module_path": modulePath, "version": "v1.0.1", "source_time": time.Now().UTC().Format(time.RFC3339Nano), "go_mod": mod, "zip_size": 1 << 20, "zip_sha256": strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	status, body = call(http.MethodPost, base+"/uploads", "application/json", oversizedBody, ownerCookies, true)
	var oversized struct {
		ID string `json:"upload_session_id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &oversized) != nil || oversized.ID == "" {
		t.Fatalf("reserve oversized test status=%d body=%s", status, body)
	}
	oversizedRequest, err := http.NewRequestWithContext(ctx, http.MethodPut, server.URL+base+"/uploads/"+oversized.ID+"/content", bytes.NewReader(bytes.Repeat([]byte{'x'}, (1<<20)+1)))
	if err != nil {
		t.Fatal(err)
	}
	oversizedRequest.ContentLength = -1
	oversizedRequest.Header.Set("Origin", server.URL)
	oversizedRequest.Header.Set("Content-Type", "application/octet-stream")
	oversizedRequest.Header.Set(csrfHeaderName, ownerCookies[csrfCookieName].Value)
	for _, cookie := range ownerCookies {
		oversizedRequest.AddCookie(cookie)
	}
	oversizedResponse, err := client.Do(oversizedRequest)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr = io.Copy(io.Discard, oversizedResponse.Body)
	closeErr = oversizedResponse.Body.Close()
	if readErr != nil || closeErr != nil || oversizedResponse.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversized Go upload status=%d read=%v close=%v", oversizedResponse.StatusCode, readErr, closeErr)
	}
	if status, body := call(http.MethodPost, base+"/uploads/"+oversized.ID+"/cancel", "", nil, ownerCookies, true); status != http.StatusNoContent {
		t.Fatalf("cancel oversized Go upload status=%d body=%s", status, body)
	}
	var rejectedArchive bytes.Buffer
	rejectedWriter := zip.NewWriter(&rejectedArchive)
	for name, content := range map[string]string{"go.mod": mod, "module.go": "package managed\n"} {
		entry, err := rejectedWriter.Create(modulePath + "@v1.0.1/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := rejectedWriter.Close(); err != nil {
		t.Fatal(err)
	}
	rejectedDigest := sha256.Sum256(rejectedArchive.Bytes())
	rejectedBody, err := json.Marshal(map[string]any{"module_path": modulePath, "version": "v1.0.1", "source_time": time.Now().UTC().Format(time.RFC3339Nano), "go_mod": mod, "zip_size": rejectedArchive.Len(), "zip_sha256": hex.EncodeToString(rejectedDigest[:])})
	if err != nil {
		t.Fatal(err)
	}
	status, body = call(http.MethodPost, base+"/uploads", "application/json", rejectedBody, ownerCookies, true)
	var rejected struct {
		ID string `json:"upload_session_id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &rejected) != nil || rejected.ID == "" {
		t.Fatalf("reserve review rejection status=%d body=%s", status, body)
	}
	if status, body := call(http.MethodPut, base+"/uploads/"+rejected.ID+"/content", "application/octet-stream", rejectedArchive.Bytes(), ownerCookies, true); status != http.StatusNoContent {
		t.Fatalf("receive review rejection status=%d body=%s", status, body)
	}
	if status, _ := call(http.MethodPost, base+"/reviews/"+rejected.ID+"/reject", "application/json", []byte(`{"reason":" "}`), reviewerCookies, true); status != http.StatusBadRequest {
		t.Fatalf("Go review rejection without a reason returned %d", status)
	}
	for range 2 {
		if status, body := call(http.MethodPost, base+"/reviews/"+rejected.ID+"/reject", "application/json", []byte(`{"reason":"synthetic rejection"}`), reviewerCookies, true); status != http.StatusNoContent {
			t.Fatalf("reject Go upload or retry status=%d body=%s", status, body)
		}
	}
	if status, body := call(http.MethodGet, base+"/uploads/"+rejected.ID, "", nil, ownerCookies, false); status != http.StatusOK || !bytes.Contains(body, []byte(`"status":"rejected"`)) {
		t.Fatalf("rejected Go receipt status=%d body=%s", status, body)
	}
	if status, _ := call(http.MethodPost, base+"/uploads/"+rejected.ID+"/publish", "", nil, ownerCookies, true); status != http.StatusNotFound {
		t.Fatalf("rejected Go upload published: %d", status)
	}
}
