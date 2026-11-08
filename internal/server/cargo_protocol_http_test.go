//go:build linux

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
)

type cargoObservedBody struct{ reads int }

func (r *cargoObservedBody) Read([]byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

func TestCargoProtocolReviewAndAuthentication(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var owner string
	if err := fixture.db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	reviewer := seedHTTPUser(t, fixture, "cargo.reviewer")
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "cargo-protocol", "Cargo protocol")
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.workspaceService.SetMembershipRole(ctx, owner, workspace.ID, reviewer, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format, review_required) VALUES (?, ?, 'cargo', 'Cargo', ?, 'now', 'now', 'cargo', 1)`, repository, workspace.ID, owner); err != nil {
		t.Fatal(err)
	}
	for _, role := range []repositories.GrantRole{repositories.GrantReader, repositories.GrantPublisher} {
		if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repository, owner, role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.repositoryService.GrantCargoReviewer(ctx, owner, workspace.ID, repository, reviewer); err != nil {
		t.Fatal(err)
	}
	readToken, err := fixture.repositoryService.IssuePersonalReadToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	writeToken, err := fixture.repositoryService.IssueCargoWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	objects, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	reservations, err := cargo.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := cargo.NewReceiptService(fixture.db, fixture.repositoryService, config.SQLite, objects, cargo.ReceiptOptions{StagingDirectory: staging, Limits: cargo.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxFiles: 100, MaxManifestBytes: 4096}, MaxConcurrent: 2, CurrentIndex: "sparse+https://registry.example/index/", DefaultIndex: "https://github.com/rust-lang/crates.io-index"})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin, CargoReservations: reservations, CargoReceipts: receipts, CargoProtocol: &CargoProtocolConfig{StagingDirectory: staging, MaxArchiveBytes: 1 << 20, MaxConcurrent: 2}})
	if err != nil {
		t.Fatal(err)
	}
	base := "/cargo/" + workspace.ID + "/" + repository
	request := func(method, path, token string, body io.Reader) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://registry.example"+path, body)
		r.Host = "registry.example"
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "192.0.2.10:54321"
		if token != "" {
			r.Header.Set("Authorization", token)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(testDeadlineResponse{ResponseRecorder: response}, r)
		return response
	}
	frame := syntheticCargoFrame(t)
	observed := &cargoObservedBody{}
	if response := request(http.MethodPut, base+"/api/v1/crates/new", readToken.Bearer, observed); response.Code != http.StatusUnauthorized || observed.reads != 0 {
		t.Fatalf("read credential consumed publication body: status=%d reads=%d", response.Code, observed.reads)
	}
	var oversized bytes.Buffer
	if err := binary.Write(&oversized, binary.LittleEndian, uint32(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := oversized.WriteString("{}"); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&oversized, binary.LittleEndian, uint32((1<<20)+1)); err != nil {
		t.Fatal(err)
	}
	if response := request(http.MethodPut, base+"/api/v1/crates/new", writeToken.Bearer, &oversized); response.Code != http.StatusBadRequest {
		t.Fatalf("oversized Cargo frame accepted: %d", response.Code)
	}
	if entries, err := os.ReadDir(staging); err != nil || len(entries) != 0 {
		t.Fatalf("invalid Cargo frame left staging entries: %d err=%v", len(entries), err)
	}
	if response := request(http.MethodPut, base+"/api/v1/crates/new", writeToken.Bearer, bytes.NewReader(frame)); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "human review required") {
		t.Fatalf("pending review reported publication success: %d", response.Code)
	}
	if response := request(http.MethodGet, base+"/index/pr/ot/protocol_fixture", readToken.Bearer, nil); response.Code != http.StatusNotFound {
		t.Fatalf("pending package was visible: %d", response.Code)
	}
	var reservationID string
	if err := fixture.db.QueryRowContext(ctx, `SELECT reservation_id FROM registry_cargo_reservations WHERE repository_id = ? AND status = 'uploaded'`, repository).Scan(&reservationID); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace.ID, repository, reservationID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	if response := request(http.MethodPut, base+"/api/v1/crates/new", writeToken.Bearer, bytes.NewReader(frame)); response.Code != http.StatusOK {
		t.Fatalf("approved Cargo retry failed: %d", response.Code)
	}
	if response := request(http.MethodPut, base+"/api/v1/crates/new", writeToken.Bearer, bytes.NewReader(frame)); response.Code != http.StatusOK {
		t.Fatalf("identical Cargo retry after publication failed: %d", response.Code)
	}
	changed := bytes.Clone(frame)
	changed[len(changed)-1] ^= 1
	if response := request(http.MethodPut, base+"/api/v1/crates/new", writeToken.Bearer, bytes.NewReader(changed)); response.Code != http.StatusConflict {
		t.Fatalf("changed Cargo publication reused existing identity: %d", response.Code)
	}
	otherWriteToken, err := fixture.repositoryService.IssueCargoWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if response := request(http.MethodPut, base+"/api/v1/crates/new", otherWriteToken.Bearer, bytes.NewReader(frame)); response.Code != http.StatusConflict {
		t.Fatalf("different Cargo credential reused existing publication: %d", response.Code)
	}
	if response := request(http.MethodGet, base+"/index/pr/ot/protocol_fixture", readToken.Bearer, nil); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"vers":"1.0.0"`) {
		t.Fatalf("published Cargo index failed: %d", response.Code)
	}
	if response := request(http.MethodGet, base+"/index/pr/ot/protocol_fixture", writeToken.Bearer, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("write credential accepted for read: %d", response.Code)
	}
	if response := request(http.MethodDelete, base+"/api/v1/crates/protocol_fixture/1.0.0/yank", writeToken.Bearer, nil); response.Code != http.StatusOK {
		t.Fatalf("Cargo yank failed: %d", response.Code)
	}
	if response := request(http.MethodGet, base+"/index/pr/ot/protocol_fixture", readToken.Bearer, nil); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"yanked":true`) {
		t.Fatalf("Cargo yank missing from index: %d", response.Code)
	}
	if response := request(http.MethodGet, base+"/api/v1/crates/protocol_fixture/1.0.0/download", readToken.Bearer, nil); response.Code != http.StatusOK || len(response.Body.Bytes()) == 0 {
		t.Fatalf("yanked Cargo archive unavailable: %d", response.Code)
	}
	wrongBase := "/cargo/" + workspace.ID + "/" + uuid.NewString()
	if response := request(http.MethodGet, wrongBase+"/index/pr/ot/protocol_fixture", readToken.Bearer, nil); response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "protocol_fixture") {
		t.Fatalf("Cargo token crossed repository scope: %d", response.Code)
	}
	if err := fixture.repositoryService.RevokeRepositoryRole(ctx, owner, workspace.ID, repository, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repository, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if response := request(http.MethodGet, base+"/index/pr/ot/protocol_fixture", readToken.Bearer, nil); response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "protocol_fixture") {
		t.Fatalf("Cargo read token revived after grant reissue: %d", response.Code)
	}
	if err := fixture.repositoryService.RevokeRepositoryRole(ctx, owner, workspace.ID, repository, owner, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if response := request(http.MethodPut, base+"/api/v1/crates/protocol_fixture/1.0.0/unyank", writeToken.Bearer, nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked Cargo write token accepted for unyank: %d", response.Code)
	}
	if entries, err := os.ReadDir(staging); err != nil || len(entries) != 0 {
		t.Fatalf("Cargo protocol left staging entries: %d err=%v", len(entries), err)
	}
}

func syntheticCargoFrame(t *testing.T) []byte {
	t.Helper()
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	manifest := []byte("[package]\nname = \"protocol_fixture\"\nversion = \"1.0.0\"\n")
	if err := tw.WriteHeader(&tar.Header{Name: "protocol_fixture-1.0.0/Cargo.toml", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	metadata := []byte(`{"name":"protocol_fixture","vers":"1.0.0","deps":[],"features":{}}`)
	var body bytes.Buffer
	if err := binary.Write(&body, binary.LittleEndian, uint32(len(metadata))); err != nil {
		t.Fatal(err)
	}
	if _, err := body.Write(metadata); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&body, binary.LittleEndian, uint32(archive.Len())); err != nil {
		t.Fatal(err)
	}
	if _, err := body.Write(archive.Bytes()); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}
