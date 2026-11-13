//go:build linux

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/npm"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
)

func TestNPMReadProtocolAuthorizationAndPublishedContent(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var owner string
	if err := fixture.db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "npm-read-protocol", "npm protocol")
	if err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'npm', 'npm', ?, 'now', 'now', 'npm')`, repository, workspace.ID, owner); err != nil {
		t.Fatal(err)
	}
	for _, role := range []repositories.GrantRole{repositories.GrantReader, repositories.GrantPublisher} {
		if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repository, owner, role); err != nil {
			t.Fatal(err)
		}
	}
	readToken, err := fixture.repositoryService.IssuePersonalReadToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	writeToken, err := fixture.repositoryService.IssueNPMWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	stage := filepath.Join(root, "staging")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	objects, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	reservations, err := npm.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := npm.NewReceiptService(fixture.db, fixture.repositoryService, config.SQLite, objects, npm.ReceiptOptions{StagingDirectory: stage, MaxConcurrent: 2, Limits: npm.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	name := "@fixture/pkg"
	manifest := []byte(`{"name":"@fixture/pkg","version":"1.0.0"}`)
	var content bytes.Buffer
	gz := gzip.NewWriter(&content)
	tarball := tar.NewWriter(gz)
	if err := tarball.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarball.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := tarball.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	digest, metadata, integrity := sha256.Sum256(content.Bytes()), sha256.Sum256(manifest), sha512.Sum512(content.Bytes())
	req := npm.ReservationRequest{Name: name, Version: "1.0.0", TarballSHA256: hex.EncodeToString(digest[:]), TarballSize: int64(content.Len()), MetadataSHA256: hex.EncodeToString(metadata[:])}
	reservation, err := reservations.Reserve(ctx, writeToken.Bearer, workspace.ID, repository, req)
	if err != nil {
		t.Fatal(err)
	}
	publication := npm.PublishDocument{Name: name, Version: req.Version, Manifest: manifest, Size: req.TarballSize, Integrity: "sha512-" + base64.StdEncoding.EncodeToString(integrity[:])}
	if err := receipts.Receive(ctx, writeToken.Bearer, workspace.ID, repository, reservation.ID, publication, bytes.NewReader(content.Bytes())); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin, NPMReservations: reservations, NPMReceipts: receipts, NPMReadProtocol: true})
	if err != nil {
		t.Fatal(err)
	}
	base := "/npm/" + workspace.ID + "/" + repository
	request := func(path, token string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "https://registry.example"+path, nil)
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "192.0.2.10:54321"
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(testDeadlineResponse{ResponseRecorder: response}, r)
		return response
	}
	if response := request(base+"/@fixture%2fpkg", readToken.Bearer); response.Code != http.StatusNotFound {
		t.Fatalf("pending npm receipt was visible: %d", response.Code)
	}
	if _, err := reservations.PublishReceipt(ctx, writeToken.Bearer, workspace.ID, repository, reservation.ID); err != nil {
		t.Fatal(err)
	}
	if response := request(base+"/@fixture%2fpkg", writeToken.Bearer); response.Code != http.StatusUnauthorized {
		t.Fatalf("write credential accessed npm metadata: %d", response.Code)
	}
	if response := request(base+"/@fixture%252fpkg", readToken.Bearer); response.Code != http.StatusNotFound {
		t.Fatalf("double-encoded npm package name accepted: %d", response.Code)
	}
	if response := request(base+"/@fixture%2fpkg?unexpected=1", readToken.Bearer); response.Code != http.StatusForbidden {
		t.Fatalf("npm metadata accepted unexpected query: %d", response.Code)
	}
	if response := request("/npm/"+workspace.ID+"/"+uuid.NewString()+"/@fixture%2fpkg", readToken.Bearer); response.Code != http.StatusUnauthorized {
		t.Fatalf("npm token accessed another repository: %d", response.Code)
	}
	foreignRequest := httptest.NewRequest(http.MethodGet, "https://other.example"+base+"/@fixture%2fpkg", nil)
	foreignRequest.TLS = &tls.ConnectionState{}
	foreignRequest.RemoteAddr = "192.0.2.10:54321"
	foreignRequest.Header.Set("Authorization", "Bearer "+readToken.Bearer)
	foreignResponse := httptest.NewRecorder()
	handler.ServeHTTP(testDeadlineResponse{ResponseRecorder: foreignResponse}, foreignRequest)
	if foreignResponse.Code != http.StatusForbidden {
		t.Fatalf("npm metadata accepted noncanonical origin: %d", foreignResponse.Code)
	}
	response := request(base+"/@fixture%2fpkg", readToken.Bearer)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("npm metadata failed: status=%d body=%s", response.Code, response.Body.String())
	}
	var packument struct {
		Versions map[string]struct {
			Dist struct {
				Tarball string `json:"tarball"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &packument); err != nil {
		t.Fatal(err)
	}
	url := packument.Versions["1.0.0"].Dist.Tarball
	if !strings.HasPrefix(url, authTestOrigin+base+"/-/tarballs/") {
		t.Fatalf("unexpected npm tarball URL: %q", url)
	}
	response = request(strings.TrimPrefix(url, authTestOrigin), readToken.Bearer)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), content.Bytes()) {
		t.Fatalf("npm tarball failed: status=%d", response.Code)
	}
	if err := fixture.repositoryService.RevokeRepositoryRole(ctx, owner, workspace.ID, repository, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if response := request(strings.TrimPrefix(url, authTestOrigin), readToken.Bearer); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked npm reader accessed tarball: %d", response.Code)
	}
}

func TestNPMPublishProtocolReviewAndAuthorization(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var owner string
	if err := fixture.db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	reviewer := seedHTTPUser(t, fixture, "npm.publish.reviewer")
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "npm-publish-http", "npm publish")
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.workspaceService.SetMembershipRole(ctx, owner, workspace.ID, reviewer, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format, review_required) VALUES (?, ?, 'npm', 'npm', ?, 'now', 'now', 'npm', 1)`, repository, workspace.ID, owner); err != nil {
		t.Fatal(err)
	}
	for _, role := range []repositories.GrantRole{repositories.GrantReader, repositories.GrantPublisher} {
		if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repository, owner, role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.repositoryService.GrantNPMReviewer(ctx, owner, workspace.ID, repository, reviewer); err != nil {
		t.Fatal(err)
	}
	readToken, err := fixture.repositoryService.IssuePersonalReadToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	writeToken, err := fixture.repositoryService.IssueNPMWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	objects, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	reservations, err := npm.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := npm.NewReceiptService(fixture.db, fixture.repositoryService, config.SQLite, objects, npm.ReceiptOptions{StagingDirectory: stage, MaxConcurrent: 2, Limits: npm.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin, NPMReservations: reservations, NPMReceipts: receipts, NPMReadProtocol: true, NPMWriteProtocol: &NPMWriteProtocolConfig{StagingDirectory: stage, MaxDocumentBytes: 2 << 20, MaxArchiveBytes: 1 << 20, MaxConcurrent: 2}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := json.RawMessage(`{"name":"@fixture/pkg","version":"1.0.0"}`)
	var content bytes.Buffer
	gz := gzip.NewWriter(&content)
	archive := tar.NewWriter(gz)
	if err := archive.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(map[string]any{"_id": "@fixture/pkg", "name": "@fixture/pkg", "versions": map[string]json.RawMessage{"1.0.0": manifest}, "dist-tags": map[string]string{"latest": "1.0.0"}, "_attachments": map[string]any{"pkg.tgz": map[string]any{"data": base64.StdEncoding.EncodeToString(content.Bytes()), "length": content.Len()}}})
	if err != nil {
		t.Fatal(err)
	}
	base := "/npm/" + workspace.ID + "/" + repository
	request := func(method, path, token string, body io.Reader) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://registry.example"+path, body)
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "192.0.2.10:54321"
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(testDeadlineResponse{ResponseRecorder: response}, r)
		return response
	}
	observed := &cargoObservedBody{}
	if response := request(http.MethodPut, base+"/@fixture%2fpkg", readToken.Bearer, observed); response.Code != http.StatusUnauthorized || observed.reads != 0 {
		t.Fatalf("npm read token consumed publish body: status=%d reads=%d", response.Code, observed.reads)
	}
	if response := request(http.MethodPut, base+"/@fixture%2fpkg", writeToken.Bearer, bytes.NewReader(document)); response.Code != http.StatusConflict {
		t.Fatalf("pending npm review reported success: %d", response.Code)
	}
	if response := request(http.MethodGet, base+"/@fixture%2fpkg", readToken.Bearer, nil); response.Code != http.StatusNotFound {
		t.Fatalf("pending npm publication was visible: %d", response.Code)
	}
	var reservationID string
	if err := fixture.db.QueryRowContext(ctx, `SELECT reservation_id FROM registry_npm_reservations WHERE repository_id = ? AND status = 'uploaded'`, repository).Scan(&reservationID); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace.ID, repository, reservationID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	if response := request(http.MethodPut, base+"/@fixture%2fpkg", writeToken.Bearer, bytes.NewReader(document)); response.Code != http.StatusForbidden {
		t.Fatalf("npm publish moved tag without grant: %d", response.Code)
	}
	if _, err := fixture.repositoryService.GrantNPMTagManager(ctx, owner, workspace.ID, repository, owner); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if response := request(http.MethodPut, base+"/@fixture%2fpkg", writeToken.Bearer, bytes.NewReader(document)); response.Code != http.StatusCreated {
			t.Fatalf("approved npm publish or retry failed: %d", response.Code)
		}
	}
	if response := request(http.MethodGet, base+"/@fixture%2fpkg", readToken.Bearer, nil); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"latest":"1.0.0"`) {
		t.Fatalf("published npm metadata missing tag: %d", response.Code)
	}
	if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
		t.Fatalf("npm publish staging not cleaned: %v", err)
	}
}

func TestNPMWriteTokenHTTPRequiresMFAAndCSRF(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var owner string
	if err := fixture.db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "npm-token-http", "npm token")
	if err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'npm', 'npm', ?, 'now', 'now', 'npm')`, repository, workspace.ID, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repository, owner, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	objects, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	reservations, err := npm.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := npm.NewReceiptService(fixture.db, fixture.repositoryService, config.SQLite, objects, npm.ReceiptOptions{StagingDirectory: stage, MaxConcurrent: 1, Limits: npm.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin, NPMReservations: reservations, NPMReceipts: receipts, NPMReadProtocol: true})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/v1/workspaces/%s/repositories/%s/npm-write-tokens", workspace.ID, repository)
	reviewBase := fmt.Sprintf("/api/v1/workspaces/%s/repositories/%s/npm", workspace.ID, repository)
	login := authHTTPRequest(handler, http.MethodPost, "/api/v1/auth/login", fmt.Sprintf(`{"login_name":%q,"password":%q}`, authTestLogin, authTestPassword), authTestOrigin, "registry.example")
	if login.Code != http.StatusOK {
		t.Fatalf("login failed: %d", login.Code)
	}
	cookies := assertSessionCookies(t, login)
	if response := authHTTPRequestWithCookies(handler, http.MethodPost, path, `{}`, authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code == http.StatusCreated {
		t.Fatal("npm token issued before MFA")
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/reviewers/"+owner, "", authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code == http.StatusOK {
		t.Fatal("npm reviewer granted before MFA")
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/tag-managers/"+owner, "", authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code == http.StatusOK {
		t.Fatal("npm tag manager granted before MFA")
	}
	begin := authHTTPRequestWithCookies(handler, http.MethodPost, "/api/v1/auth/mfa/enrollment", "", authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value)
	if begin.Code != http.StatusOK {
		t.Fatalf("MFA enrollment failed: %d", begin.Code)
	}
	var enrollment enrollmentResponse
	if err := json.Unmarshal(begin.Body.Bytes(), &enrollment); err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	complete := authHTTPRequestWithCookies(handler, http.MethodPost, "/api/v1/auth/mfa/enrollment/complete", fmt.Sprintf(`{"code":%q}`, authHTTPOTP(secret, time.Now().Unix()/30)), authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value)
	if complete.Code != http.StatusOK {
		t.Fatalf("MFA completion failed: %d", complete.Code)
	}
	cookies = assertSessionCookies(t, complete)
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/reviewers/"+owner, "", authTestOrigin, "registry.example", cookies, ""); response.Code == http.StatusOK {
		t.Fatal("npm reviewer granted without CSRF")
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/reviewers/"+owner, "", authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code != http.StatusOK {
		t.Fatalf("npm reviewer grant failed: %d", response.Code)
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/tag-managers/"+owner, "", authTestOrigin, "registry.example", cookies, ""); response.Code == http.StatusOK {
		t.Fatal("npm tag manager granted without CSRF")
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/tag-managers/"+owner, "", authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code != http.StatusOK {
		t.Fatalf("npm tag manager grant failed: %d", response.Code)
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/tags", `{"name":"fixture","tag":"latest","version":"1.0.0","expected_revision":0}`, authTestOrigin, "registry.example", cookies, ""); response.Code == http.StatusOK {
		t.Fatal("npm tag changed without CSRF")
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/review-policy", `{"required":true,"expected_revision":0}`, authTestOrigin, "registry.example", cookies, ""); response.Code == http.StatusOK {
		t.Fatal("npm review policy changed without CSRF")
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/review-policy", `{"required":true,"expected_revision":0}`, authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code != http.StatusOK {
		t.Fatalf("npm review policy change failed: %d", response.Code)
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPost, path, `{}`, authTestOrigin, "registry.example", cookies, ""); response.Code == http.StatusCreated {
		t.Fatal("npm token issued without CSRF")
	}
	issued := authHTTPRequestWithCookies(handler, http.MethodPost, path, `{}`, authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value)
	if issued.Code != http.StatusCreated {
		t.Fatalf("npm token issuance failed: %d", issued.Code)
	}
	var credential issuedPersonalTokenResponse
	if err := json.Unmarshal(issued.Body.Bytes(), &credential); err != nil || credential.Token.TokenID == "" || credential.Bearer == "" {
		t.Fatal("npm token response invalid")
	}
	manifest := []byte(`{"name":"fixture","version":"1.0.0"}`)
	var content bytes.Buffer
	gz := gzip.NewWriter(&content)
	archive := tar.NewWriter(gz)
	if err := archive.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	digest, metadata, integrity := sha256.Sum256(content.Bytes()), sha256.Sum256(manifest), sha512.Sum512(content.Bytes())
	publishRequest := npm.ReservationRequest{Name: "fixture", Version: "1.0.0", TarballSHA256: hex.EncodeToString(digest[:]), TarballSize: int64(content.Len()), MetadataSHA256: hex.EncodeToString(metadata[:])}
	reservation, err := reservations.Reserve(ctx, credential.Bearer, workspace.ID, repository, publishRequest)
	if err != nil {
		t.Fatal(err)
	}
	publication := npm.PublishDocument{Name: publishRequest.Name, Version: publishRequest.Version, Manifest: manifest, Size: publishRequest.TarballSize, Integrity: "sha512-" + base64.StdEncoding.EncodeToString(integrity[:])}
	if err := receipts.Receive(ctx, credential.Bearer, workspace.ID, repository, reservation.ID, publication, bytes.NewReader(content.Bytes())); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.PublishReceipt(ctx, credential.Bearer, workspace.ID, repository, reservation.ID); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("npm publication unexpectedly skipped review: %v", err)
	}
	if _, err := fixture.repositoryService.SetNPMReviewPolicy(ctx, owner, workspace.ID, repository, 1, false); err != nil {
		t.Fatal(err)
	}
	// The existing review hold remains active after policy changes; use a new
	// receipt to exercise tags without bypassing the pending human decision.
	publishRequest.Name = "published"
	manifest = []byte(`{"name":"published","version":"1.0.0"}`)
	content.Reset()
	gz = gzip.NewWriter(&content)
	archive = tar.NewWriter(gz)
	if err := archive.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	digest, metadata, integrity = sha256.Sum256(content.Bytes()), sha256.Sum256(manifest), sha512.Sum512(content.Bytes())
	publishRequest.TarballSHA256, publishRequest.MetadataSHA256, publishRequest.TarballSize = hex.EncodeToString(digest[:]), hex.EncodeToString(metadata[:]), int64(content.Len())
	reservation, err = reservations.Reserve(ctx, credential.Bearer, workspace.ID, repository, publishRequest)
	if err != nil {
		t.Fatal(err)
	}
	publication = npm.PublishDocument{Name: publishRequest.Name, Version: publishRequest.Version, Manifest: manifest, Size: publishRequest.TarballSize, Integrity: "sha512-" + base64.StdEncoding.EncodeToString(integrity[:])}
	if err := receipts.Receive(ctx, credential.Bearer, workspace.ID, repository, reservation.ID, publication, bytes.NewReader(content.Bytes())); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.PublishReceipt(ctx, credential.Bearer, workspace.ID, repository, reservation.ID); err != nil {
		t.Fatal(err)
	}
	tagPayload := `{"name":"published","tag":"latest","version":"1.0.0","expected_revision":0}`
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/tags", tagPayload, authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code != http.StatusOK {
		t.Fatalf("npm tag creation failed: %d", response.Code)
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/tags", tagPayload, authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code != http.StatusConflict {
		t.Fatalf("stale npm tag update was accepted: %d", response.Code)
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodGet, reviewBase+"/tags/state?name=published&tag=latest", "", authTestOrigin, "registry.example", cookies, ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"revision":1`) {
		t.Fatalf("npm tag state failed: %d", response.Code)
	}
	removePayload := `{"name":"published","tag":"latest","expected_revision":1}`
	if response := authHTTPRequestWithCookies(handler, http.MethodDelete, reviewBase+"/tags", removePayload, authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code != http.StatusOK {
		t.Fatalf("npm tag removal failed: %d", response.Code)
	}
	listed := authHTTPRequestWithCookies(handler, http.MethodGet, "/api/v1/npm-write-tokens", "", authTestOrigin, "registry.example", cookies, "")
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), credential.Bearer) || !strings.Contains(listed.Body.String(), credential.Token.TokenID) {
		t.Fatalf("npm token metadata listing invalid: %d", listed.Code)
	}
	revokePath := "/api/v1/npm-write-tokens/" + credential.Token.TokenID
	if response := authHTTPRequestWithCookies(handler, http.MethodDelete, revokePath, "", authTestOrigin, "registry.example", cookies, ""); response.Code == http.StatusNoContent {
		t.Fatal("npm token revoked without CSRF")
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodDelete, revokePath, "", authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code != http.StatusNoContent {
		t.Fatalf("npm token revocation failed: %d", response.Code)
	}
}
