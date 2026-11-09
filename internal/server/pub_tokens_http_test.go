//go:build linux

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/pub"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
)

func TestPubWriteTokenHTTPRequiresMFAAndCSRF(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var owner string
	if err := fixture.db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "pub-token-http", "Pub token")
	if err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'pub', 'Pub', ?, 'now', 'now', 'pub')`, repository, workspace.ID, owner); err != nil {
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
	reservations, err := pub.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	limits := pub.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}
	receipts, err := pub.NewReceiptService(fixture.db, fixture.repositoryService, config.SQLite, objects, pub.ReceiptOptions{StagingDirectory: stage, MaxConcurrent: 1, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin, PubReservations: reservations, PubReceipts: receipts, PubReadProtocol: true, PubWriteProtocol: &PubWriteProtocolConfig{StagingDirectory: stage, MaxArchiveBytes: 1 << 20, MaxConcurrent: 1, Limits: limits}})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/v1/workspaces/%s/repositories/%s/pub-write-tokens", workspace.ID, repository)
	reviewBase := fmt.Sprintf("/api/v1/workspaces/%s/repositories/%s/pub", workspace.ID, repository)
	login := authHTTPRequest(handler, http.MethodPost, "/api/v1/auth/login", fmt.Sprintf(`{"login_name":%q,"password":%q}`, authTestLogin, authTestPassword), authTestOrigin, "registry.example")
	if login.Code != http.StatusOK {
		t.Fatalf("login failed: %d", login.Code)
	}
	cookies := assertSessionCookies(t, login)
	if response := authHTTPRequestWithCookies(handler, http.MethodPost, path, `{}`, authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code == http.StatusCreated {
		t.Fatal("Pub token issued before MFA")
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/reviewers/"+owner, "", authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code == http.StatusOK {
		t.Fatal("Pub reviewer granted before MFA")
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
		t.Fatal("Pub reviewer granted without CSRF")
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/reviewers/"+owner, "", authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code != http.StatusOK {
		t.Fatalf("Pub reviewer grant failed: %d", response.Code)
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/review-policy", `{"required":true,"expected_revision":0}`, authTestOrigin, "registry.example", cookies, ""); response.Code == http.StatusOK {
		t.Fatal("Pub review policy changed without CSRF")
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPut, reviewBase+"/review-policy", `{"required":true,"expected_revision":0}`, authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code != http.StatusOK {
		t.Fatalf("Pub review policy change failed: %d", response.Code)
	}
	publisher := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (?, 'Synthetic publisher', 'now', 'now')`, publisher); err != nil {
		t.Fatal(err)
	}
	if err := fixture.workspaceService.SetMembershipRole(ctx, owner, workspace.ID, publisher, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repository, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	publisherToken, err := fixture.repositoryService.IssuePubWriteToken(ctx, publisher, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("name: review_fixture\nversion: 1.0.0\n")
	var content bytes.Buffer
	compressor := gzip.NewWriter(&content)
	archive := tar.NewWriter(compressor)
	if err := archive.WriteHeader(&tar.Header{Name: "pubspec.yaml", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	digest, metadata := sha256.Sum256(content.Bytes()), sha256.Sum256(manifest)
	reservation, err := reservations.Reserve(ctx, publisherToken.Bearer, workspace.ID, repository, pub.ReservationRequest{Name: "review_fixture", Version: "1.0.0", TarballSHA256: hex.EncodeToString(digest[:]), TarballSize: int64(content.Len()), MetadataSHA256: hex.EncodeToString(metadata[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.Receive(ctx, publisherToken.Bearer, workspace.ID, repository, reservation.ID, pub.ReceiptInput{Name: "review_fixture", Version: "1.0.0", Manifest: manifest, Size: int64(content.Len())}, bytes.NewReader(content.Bytes())); err != nil {
		t.Fatal(err)
	}
	listedReviews := authHTTPRequestWithCookies(handler, http.MethodGet, reviewBase+"/reviews", "", authTestOrigin, "registry.example", cookies, "")
	if listedReviews.Code != http.StatusOK || !strings.Contains(listedReviews.Body.String(), reservation.ID) {
		t.Fatalf("pending Pub review missing: %d", listedReviews.Code)
	}
	approve := reviewBase + "/reviews/" + reservation.ID + "/approve"
	if response := authHTTPRequestWithCookies(handler, http.MethodPost, approve, "", authTestOrigin, "registry.example", cookies, ""); response.Code == http.StatusNoContent {
		t.Fatal("Pub review approved without CSRF")
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPost, approve, "", authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code != http.StatusNoContent {
		t.Fatalf("Pub review approval failed: %d", response.Code)
	}
	if _, err := reservations.PublishReceipt(ctx, publisherToken.Bearer, workspace.ID, repository, reservation.ID); err != nil {
		t.Fatalf("approved Pub receipt failed publication: %v", err)
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodPost, path, `{}`, authTestOrigin, "registry.example", cookies, ""); response.Code == http.StatusCreated {
		t.Fatal("Pub token issued without CSRF")
	}
	issued := authHTTPRequestWithCookies(handler, http.MethodPost, path, `{}`, authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value)
	var credential issuedPersonalTokenResponse
	if issued.Code != http.StatusCreated || json.Unmarshal(issued.Body.Bytes(), &credential) != nil || credential.Bearer == "" || credential.Token.TokenID == "" {
		t.Fatalf("Pub token issuance failed: %d", issued.Code)
	}
	listed := authHTTPRequestWithCookies(handler, http.MethodGet, "/api/v1/pub-write-tokens", "", authTestOrigin, "registry.example", cookies, "")
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), credential.Bearer) || !strings.Contains(listed.Body.String(), credential.Token.TokenID) {
		t.Fatalf("Pub token metadata listing invalid: %d", listed.Code)
	}
	revokePath := "/api/v1/pub-write-tokens/" + credential.Token.TokenID
	if response := authHTTPRequestWithCookies(handler, http.MethodDelete, revokePath, "", authTestOrigin, "registry.example", cookies, ""); response.Code == http.StatusNoContent {
		t.Fatal("Pub token revoked without CSRF")
	}
	if response := authHTTPRequestWithCookies(handler, http.MethodDelete, revokePath, "", authTestOrigin, "registry.example", cookies, cookies[csrfCookieName].Value); response.Code != http.StatusNoContent {
		t.Fatalf("Pub token revocation failed: %d", response.Code)
	}
	if _, err := reservations.StartNativeUpload(ctx, credential.Bearer, workspace.ID, repository); !errors.Is(err, repositories.ErrPubWriteTokenUnavailable) {
		t.Fatalf("revoked Pub credential remained usable: %v", err)
	}
}
