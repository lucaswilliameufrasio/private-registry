//go:build linux

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
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
)

type observedPubUploadBody struct {
	reads int
}

type revokePubUploadBody struct {
	source io.Reader
	revoke func() error
	called bool
}

func (r *revokePubUploadBody) Read(p []byte) (int, error) {
	if !r.called {
		r.called = true
		if err := r.revoke(); err != nil {
			return 0, err
		}
	}
	return r.source.Read(p)
}

func (r *revokePubUploadBody) Close() error {
	return nil
}

func (r *observedPubUploadBody) Read([]byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

func (r *observedPubUploadBody) Close() error {
	return nil
}

func TestPubReadProtocolAuthorizationAndContent(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var owner string
	if err := fixture.db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "pub-read-protocol", "Pub protocol")
	if err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'pub', 'Pub', ?, 'now', 'now', 'pub')`, repository, workspace.ID, owner); err != nil {
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
	writeToken, err := fixture.repositoryService.IssuePubWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
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
	reservations, err := pub.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := pub.NewReceiptService(fixture.db, fixture.repositoryService, config.SQLite, objects, pub.ReceiptOptions{StagingDirectory: stage, MaxConcurrent: 1, Limits: pub.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("name: fixture\nversion: 1.0.0\n")
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	w := tar.NewWriter(gz)
	if err := w.WriteHeader(&tar.Header{Name: "pubspec.yaml", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	digest, metadata := sha256.Sum256(archive.Bytes()), sha256.Sum256(manifest)
	reservation, err := reservations.Reserve(ctx, writeToken.Bearer, workspace.ID, repository, pub.ReservationRequest{Name: "fixture", Version: "1.0.0", TarballSHA256: hex.EncodeToString(digest[:]), TarballSize: int64(archive.Len()), MetadataSHA256: hex.EncodeToString(metadata[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.Receive(ctx, writeToken.Bearer, workspace.ID, repository, reservation.ID, pub.ReceiptInput{Name: "fixture", Version: "1.0.0", Manifest: manifest, Size: int64(archive.Len())}, bytes.NewReader(archive.Bytes())); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin, PubReservations: reservations, PubReceipts: receipts, PubReadProtocol: true, PubWriteProtocol: &PubWriteProtocolConfig{StagingDirectory: stage, MaxArchiveBytes: 1 << 20, MaxConcurrent: 1, Limits: pub.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}}})
	if err != nil {
		t.Fatal(err)
	}
	base := "/pub/" + workspace.ID + "/" + repository
	request := func(path, token string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, authTestOrigin+path, nil)
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "192.0.2.10:54321"
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(testDeadlineResponse{ResponseRecorder: response}, r)
		return response
	}
	path := base + "/api/packages/fixture"
	if response := request(path, readToken.Bearer); response.Code != http.StatusNotFound {
		t.Fatalf("pending Pub receipt was visible: %d", response.Code)
	}
	if _, err := reservations.PublishReceipt(ctx, writeToken.Bearer, workspace.ID, repository, reservation.ID); err != nil {
		t.Fatal(err)
	}
	start := request(base+"/api/packages/versions/new", writeToken.Bearer)
	var session struct {
		URL    string            `json:"url"`
		Fields map[string]string `json:"fields"`
	}
	if start.Code != http.StatusOK || json.Unmarshal(start.Body.Bytes(), &session) != nil || session.Fields["upload_id"] == "" {
		t.Fatalf("Pub native start failed: %d %s", start.Code, start.Body.String())
	}
	for _, attempt := range []struct {
		name   string
		url    string
		token  string
		status int
	}{
		{"invalid token", session.URL, "invalid", http.StatusUnauthorized},
		{"invalid session", authTestOrigin + base + "/api/uploads/" + uuid.NewString(), writeToken.Bearer, http.StatusNotFound},
	} {
		t.Run(attempt.name, func(t *testing.T) {
			body := &observedPubUploadBody{}
			r := httptest.NewRequest(http.MethodPost, attempt.url, nil)
			r.Body = body
			r.TLS = &tls.ConnectionState{}
			r.RemoteAddr = "192.0.2.10:54321"
			r.Header.Set("Authorization", "Bearer "+attempt.token)
			r.Header.Set("Content-Type", "multipart/form-data; boundary=fixture")
			result := httptest.NewRecorder()
			handler.ServeHTTP(testDeadlineResponse{ResponseRecorder: result}, r)
			if result.Code != attempt.status || body.reads != 0 {
				t.Fatalf("unauthorized upload consumed body: status=%d reads=%d", result.Code, body.reads)
			}
		})
	}
	var multipartBody bytes.Buffer
	multi := multipart.NewWriter(&multipartBody)
	if err := multi.WriteField("upload_id", session.Fields["upload_id"]); err != nil {
		t.Fatal(err)
	}
	part, err := multi.CreateFormFile("file", "package.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(archive.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := multi.Close(); err != nil {
		t.Fatal(err)
	}
	post := httptest.NewRequest(http.MethodPost, session.URL, bytes.NewReader(multipartBody.Bytes()))
	post.TLS = &tls.ConnectionState{}
	post.RemoteAddr = "192.0.2.10:54321"
	post.Header.Set("Authorization", "Bearer "+writeToken.Bearer)
	post.Header.Set("Content-Type", multi.FormDataContentType())
	posted := httptest.NewRecorder()
	handler.ServeHTTP(testDeadlineResponse{ResponseRecorder: posted}, post)
	if posted.Code != http.StatusNoContent {
		t.Fatalf("Pub native upload retry failed: %d %s", posted.Code, posted.Body.String())
	}
	finalized := request(strings.TrimPrefix(posted.Header().Get("Location"), authTestOrigin), writeToken.Bearer)
	if finalized.Code != http.StatusOK {
		t.Fatalf("Pub native finalization retry failed: %d %s", finalized.Code, finalized.Body.String())
	}
	if _, err := fixture.repositoryService.SetPubReviewPolicy(ctx, owner, workspace.ID, repository, 0, true); err != nil {
		t.Fatal(err)
	}
	pendingManifest := []byte("name: pending_fixture\nversion: 1.0.0\n")
	var pendingArchive bytes.Buffer
	pendingGzip := gzip.NewWriter(&pendingArchive)
	pendingTar := tar.NewWriter(pendingGzip)
	if err := pendingTar.WriteHeader(&tar.Header{Name: "pubspec.yaml", Mode: 0o600, Size: int64(len(pendingManifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := pendingTar.Write(pendingManifest); err != nil {
		t.Fatal(err)
	}
	if err := pendingTar.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pendingGzip.Close(); err != nil {
		t.Fatal(err)
	}
	start = request(base+"/api/packages/versions/new", writeToken.Bearer)
	if start.Code != http.StatusOK || json.Unmarshal(start.Body.Bytes(), &session) != nil {
		t.Fatalf("Pub pending session failed: %d", start.Code)
	}
	multipartBody.Reset()
	multi = multipart.NewWriter(&multipartBody)
	if err := multi.WriteField("upload_id", session.Fields["upload_id"]); err != nil {
		t.Fatal(err)
	}
	part, err = multi.CreateFormFile("file", "package.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(pendingArchive.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := multi.Close(); err != nil {
		t.Fatal(err)
	}
	post = httptest.NewRequest(http.MethodPost, session.URL, bytes.NewReader(multipartBody.Bytes()))
	post.TLS = &tls.ConnectionState{}
	post.RemoteAddr = "192.0.2.10:54321"
	post.Header.Set("Authorization", "Bearer "+writeToken.Bearer)
	post.Header.Set("Content-Type", multi.FormDataContentType())
	posted = httptest.NewRecorder()
	handler.ServeHTTP(testDeadlineResponse{ResponseRecorder: posted}, post)
	if posted.Code != http.StatusNoContent {
		t.Fatalf("Pub pending upload failed: %d %s", posted.Code, posted.Body.String())
	}
	finalized = request(strings.TrimPrefix(posted.Header().Get("Location"), authTestOrigin), writeToken.Bearer)
	if finalized.Code != http.StatusConflict || !strings.Contains(finalized.Body.String(), "REVIEW_REQUIRED") {
		t.Fatalf("Pub pending review reported success: %d %s", finalized.Code, finalized.Body.String())
	}
	var pendingVersions int
	if err := fixture.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_pub_packages WHERE repository_id = ? AND name = 'pending_fixture'`, repository).Scan(&pendingVersions); err != nil || pendingVersions != 0 {
		t.Fatalf("Pub pending package was published: count=%d err=%v", pendingVersions, err)
	}
	revokedToken, err := fixture.repositoryService.IssuePubWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	start = request(base+"/api/packages/versions/new", revokedToken.Bearer)
	if start.Code != http.StatusOK || json.Unmarshal(start.Body.Bytes(), &session) != nil {
		t.Fatalf("Pub revocation session failed: %d", start.Code)
	}
	multipartBody.Reset()
	multi = multipart.NewWriter(&multipartBody)
	if err := multi.WriteField("upload_id", session.Fields["upload_id"]); err != nil {
		t.Fatal(err)
	}
	part, err = multi.CreateFormFile("file", "package.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(pendingArchive.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := multi.Close(); err != nil {
		t.Fatal(err)
	}
	post = httptest.NewRequest(http.MethodPost, session.URL, nil)
	post.Body = &revokePubUploadBody{source: bytes.NewReader(multipartBody.Bytes()), revoke: func() error {
		return fixture.repositoryService.RevokePubWriteToken(ctx, owner, revokedToken.ID)
	}}
	post.TLS = &tls.ConnectionState{}
	post.RemoteAddr = "192.0.2.10:54321"
	post.Header.Set("Authorization", "Bearer "+revokedToken.Bearer)
	post.Header.Set("Content-Type", multi.FormDataContentType())
	posted = httptest.NewRecorder()
	handler.ServeHTTP(testDeadlineResponse{ResponseRecorder: posted}, post)
	if posted.Code != http.StatusUnauthorized {
		t.Fatalf("Pub upload ignored credential revocation while reading: %d", posted.Code)
	}
	var nativeReservation sql.NullString
	if err := fixture.db.QueryRowContext(ctx, `SELECT reservation_id FROM registry_pub_native_uploads WHERE upload_id = ?`, session.Fields["upload_id"]).Scan(&nativeReservation); err != nil || nativeReservation.Valid {
		t.Fatalf("revoked Pub upload bound reservation: valid=%v err=%v", nativeReservation.Valid, err)
	}
	if response := request(path, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated Pub metadata request: %d", response.Code)
	}
	if response := request(path, writeToken.Bearer); response.Code != http.StatusOK {
		t.Fatalf("Pub publisher with reader grant could not access metadata: %d", response.Code)
	}
	if response := request(path+"?unexpected=1", readToken.Bearer); response.Code != http.StatusForbidden {
		t.Fatalf("Pub metadata accepted unexpected query: %d", response.Code)
	}
	response := request(path, readToken.Bearer)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("Pub metadata failed: status=%d", response.Code)
	}
	var data struct {
		Latest struct {
			ArchiveURL    string `json:"archive_url"`
			ArchiveSHA256 string `json:"archive_sha256"`
		} `json:"latest"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &data); err != nil || data.Latest.ArchiveSHA256 != hex.EncodeToString(digest[:]) || !strings.HasPrefix(data.Latest.ArchiveURL, authTestOrigin+base+"/packages/fixture/") {
		t.Fatalf("Pub metadata response invalid: %v", err)
	}
	response = request(strings.TrimPrefix(data.Latest.ArchiveURL, authTestOrigin), readToken.Bearer)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), archive.Bytes()) {
		t.Fatalf("Pub archive response failed: %d", response.Code)
	}
	if err := fixture.repositoryService.RevokeRepositoryRole(ctx, owner, workspace.ID, repository, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if response := request(path, readToken.Bearer); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked Pub reader accessed metadata: %d", response.Code)
	}
	if response := request(path, writeToken.Bearer); response.Code != http.StatusForbidden {
		t.Fatalf("Pub publisher without reader grant accessed metadata: %d", response.Code)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repository, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if response := request(path, writeToken.Bearer); response.Code != http.StatusForbidden {
		t.Fatalf("reader regrant revived Pub publisher metadata access: %d", response.Code)
	}
	newWriteToken, err := fixture.repositoryService.IssuePubWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if response := request(path, newWriteToken.Bearer); response.Code != http.StatusOK {
		t.Fatalf("new Pub publisher token did not bind new reader grant: %d", response.Code)
	}
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_pub_write_tokens SET reader_grant_id = NULL WHERE token_id = ?`, newWriteToken.ID); err == nil {
		t.Fatal("Pub publisher token reader grant was mutable")
	}
}
