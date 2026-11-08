//go:build linux && integration

package server

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
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

func TestNPMPublishProtocolRealClientReviewedPublication(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var owner string
	if err := fixture.db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	reviewer := seedHTTPUser(t, fixture, "npm.client.reviewer")
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "npm-client-publish", "npm client")
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
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repository, owner, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repository, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantNPMReviewer(ctx, owner, workspace.ID, repository, reviewer); err != nil {
		t.Fatal(err)
	}
	token, err := fixture.repositoryService.IssueNPMWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	readToken, err := fixture.repositoryService.IssuePersonalReadToken(ctx, owner, workspace.ID, repository, time.Hour)
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
	var handler http.Handler
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		handler.ServeHTTP(response, request)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	handler, err = NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: server.URL, AssetOrigin: "https://assets.example", NPMReservations: reservations, NPMReceipts: receipts, NPMReadProtocol: true, NPMWriteProtocol: &NPMWriteProtocolConfig{StagingDirectory: stage, MaxDocumentBytes: 2 << 20, MaxArchiveBytes: 1 << 20, MaxConcurrent: 2}})
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	registry := server.URL + "/npm/" + workspace.ID + "/" + repository + "/"
	parsed, err := url.Parse(registry)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "npmrc")
	configuration := fmt.Sprintf("registry=%s\n//%s%s:_authToken=%s\naudit=false\nfund=false\nupdate-notifier=false\n", registry, parsed.Host, parsed.Path, token.Bearer)
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"name":"@fixture/publish","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "index.js"), []byte("module.exports = 1;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		t.Fatal(err)
	}
	invoke := func() ([]byte, error) {
		command := exec.CommandContext(ctx, npmPath, "publish", "--ignore-scripts", "--no-audit", "--json")
		command.Dir = project
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "NPM_CONFIG_USERCONFIG=" + configPath, "NPM_CONFIG_CACHE=" + filepath.Join(root, "cache"), "NODE_EXTRA_CA_CERTS=" + caPath, "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost"}
		return command.CombinedOutput()
	}
	if output, err := invoke(); err == nil {
		t.Fatalf("npm publish reported success before review: %s", strings.ReplaceAll(string(output), token.Bearer, "[redacted]"))
	}
	var reservationID string
	if err := fixture.db.QueryRowContext(ctx, `SELECT reservation_id FROM registry_npm_reservations WHERE repository_id = ? AND status = 'uploaded'`, repository).Scan(&reservationID); err != nil {
		t.Fatalf("pending receipt missing: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace.ID, repository, reservationID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	if output, err := invoke(); err == nil {
		t.Fatalf("npm publish reported success without tag grant: %s", strings.ReplaceAll(string(output), token.Bearer, "[redacted]"))
	}
	var publishedCount int
	if err := fixture.db.QueryRowContext(ctx, `SELECT count(*) FROM registry_npm_versions WHERE repository_id = ?`, repository).Scan(&publishedCount); err != nil || publishedCount != 0 {
		t.Fatalf("denied npm tag grant left published version: count=%d err=%v", publishedCount, err)
	}
	if _, err := fixture.repositoryService.GrantNPMTagManager(ctx, owner, workspace.ID, repository, owner); err != nil {
		t.Fatal(err)
	}
	if output, err := invoke(); err != nil {
		t.Fatalf("approved npm publish failed: %v output=%s", err, strings.ReplaceAll(string(output), token.Bearer, "[redacted]"))
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"name":"@fixture/publish","version":"2.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := invoke(); err == nil {
		t.Fatalf("second npm version skipped review: %s", strings.ReplaceAll(string(output), token.Bearer, "[redacted]"))
	}
	var secondReservation string
	if err := fixture.db.QueryRowContext(ctx, `SELECT reservation_id FROM registry_npm_reservations WHERE repository_id = ? AND version_identity = '2.0.0' AND status = 'uploaded'`, repository).Scan(&secondReservation); err != nil {
		t.Fatalf("second pending receipt missing: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace.ID, repository, secondReservation, "approved", ""); err != nil {
		t.Fatal(err)
	}
	if output, err := invoke(); err != nil {
		t.Fatalf("second reviewed npm publish failed: %v output=%s", err, strings.ReplaceAll(string(output), token.Bearer, "[redacted]"))
	}
	if _, err := reservations.PublishReceiptWithInitialTags(ctx, token.Bearer, workspace.ID, repository, reservationID, map[string]string{"latest": "1.0.0"}); !errors.Is(err, npm.ErrTagConflict) {
		t.Fatalf("old receipt retry moved latest backwards: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"name":"@fixture/publish","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := invoke(); err == nil {
		t.Fatalf("old npm publication retry moved latest backwards: %s", strings.ReplaceAll(string(output), token.Bearer, "[redacted]"))
	}
	readConfigPath := filepath.Join(root, "npm-read-config")
	readConfig := fmt.Sprintf("registry=%s\n//%s%s:_authToken=%s\naudit=false\nfund=false\nupdate-notifier=false\n", registry, parsed.Host, parsed.Path, readToken.Bearer)
	if err := os.WriteFile(readConfigPath, []byte(readConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	consumer := filepath.Join(root, "consumer")
	if err := os.Mkdir(consumer, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(consumer, "package.json"), []byte(`{"name":"synthetic-consumer","version":"1.0.0","private":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	install := exec.CommandContext(ctx, npmPath, "install", "@fixture/publish", "--ignore-scripts", "--no-audit", "--no-fund")
	install.Dir = consumer
	install.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "NPM_CONFIG_USERCONFIG=" + readConfigPath, "NPM_CONFIG_CACHE=" + filepath.Join(root, "read-cache"), "NODE_EXTRA_CA_CERTS=" + caPath, "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost"}
	output, err := install.CombinedOutput()
	if err != nil {
		t.Fatalf("npm install of published package failed: %v output=%s", err, strings.ReplaceAll(string(output), readToken.Bearer, "[redacted]"))
	}
	installed, err := os.ReadFile(filepath.Join(consumer, "node_modules", "@fixture", "publish", "index.js"))
	if err != nil || string(installed) != "module.exports = 1;\n" {
		t.Fatalf("installed npm package differs: %v", err)
	}
	installedManifest, err := os.ReadFile(filepath.Join(consumer, "node_modules", "@fixture", "publish", "package.json"))
	if err != nil || !strings.Contains(string(installedManifest), `"version":"2.0.0"`) {
		t.Fatalf("npm latest did not resolve to second version: %v", err)
	}
}
