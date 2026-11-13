//go:build linux && integration

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
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
)

func TestNPMReadProtocolRealClientInstall(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var owner string
	if err := fixture.db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "npm-client-read", "npm client")
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
	corruptStore := &syntheticCorruptCargoStore{Driver: objects}
	receipts, err := npm.NewReceiptService(fixture.db, fixture.repositoryService, config.SQLite, corruptStore, npm.ReceiptOptions{StagingDirectory: stage, MaxConcurrent: 2, Limits: npm.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	name := "@fixture/pkg"
	manifest := []byte(`{"name":"@fixture/pkg","version":"1.0.0"}`)
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
	req := npm.ReservationRequest{Name: name, Version: "1.0.0", TarballSHA256: hex.EncodeToString(digest[:]), TarballSize: int64(content.Len()), MetadataSHA256: hex.EncodeToString(metadata[:])}
	reservation, err := reservations.Reserve(ctx, writeToken.Bearer, workspace.ID, repository, req)
	if err != nil {
		t.Fatal(err)
	}
	publication := npm.PublishDocument{Name: name, Version: req.Version, Manifest: manifest, Size: req.TarballSize, Integrity: "sha512-" + base64.StdEncoding.EncodeToString(integrity[:])}
	if err := receipts.Receive(ctx, writeToken.Bearer, workspace.ID, repository, reservation.ID, publication, bytes.NewReader(content.Bytes())); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.PublishReceipt(ctx, writeToken.Bearer, workspace.ID, repository, reservation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantNPMTagManager(ctx, owner, workspace.ID, repository, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.SetDistTag(ctx, owner, workspace.ID, repository, name, "latest", req.Version, 0); err != nil {
		t.Fatal(err)
	}
	var handler http.Handler
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		handler.ServeHTTP(response, request)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	handler, err = NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: server.URL, AssetOrigin: "https://assets.example", NPMReservations: reservations, NPMReceipts: receipts, NPMReadProtocol: true})
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
	configuration := fmt.Sprintf("registry=%s\n//%s%s:_authToken=%s\naudit=false\nfund=false\nupdate-notifier=false\n", registry, parsed.Host, parsed.Path, readToken.Bearer)
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"name":"synthetic-consumer","version":"1.0.0","private":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, npmPath, "install", "@fixture/pkg", "--ignore-scripts", "--no-audit", "--no-fund")
	command.Dir = project
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "NPM_CONFIG_USERCONFIG=" + configPath, "NPM_CONFIG_CACHE=" + filepath.Join(root, "cache"), "NODE_EXTRA_CA_CERTS=" + caPath, "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("npm install failed: %v output=%s", err, strings.ReplaceAll(string(output), readToken.Bearer, "[redacted]"))
	}
	installed, err := os.ReadFile(filepath.Join(project, "node_modules", "@fixture", "pkg", "package.json"))
	if err != nil || !bytes.Equal(installed, manifest) {
		t.Fatalf("installed npm package differs: %v", err)
	}
	corruptStore.corrupt.Store(true)
	corruptProject := filepath.Join(root, "corrupt-consumer")
	if err := os.Mkdir(corruptProject, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corruptProject, "package.json"), []byte(`{"name":"corrupt-consumer","version":"1.0.0","private":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	corruptInstall := exec.CommandContext(ctx, npmPath, "install", "@fixture/pkg@1.0.0", "--ignore-scripts", "--no-audit", "--no-fund")
	corruptInstall.Dir = corruptProject
	corruptInstall.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "NPM_CONFIG_USERCONFIG=" + configPath, "NPM_CONFIG_CACHE=" + filepath.Join(root, "corrupt-cache"), "NPM_CONFIG_FETCH_RETRIES=0", "NODE_EXTRA_CA_CERTS=" + caPath, "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost"}
	if output, err := corruptInstall.CombinedOutput(); err == nil {
		t.Fatalf("npm accepted corrupt tarball: %s", strings.ReplaceAll(string(output), readToken.Bearer, "[redacted]"))
	}
}
