//go:build integration && linux

package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/repositories"
	"private-registry/internal/workspaces"
)

const ociToolsRoot = "/tmp/opencode/private-registry-oci-tools"

// TestExperimentalOCIServeRealClientJourney pushes and pulls with the real
// ORAS client through the real serve command behind a local TLS front. The
// fixture prepares the user, grants and tokens directly; it does not cover the
// administrative journey, Docker/containerd clients or any recovery path.
func TestExperimentalOCIServeRealClientJourney(t *testing.T) {
	oras := filepath.Join(ociToolsRoot, "oras")
	if _, err := os.Stat(oras); err != nil {
		t.Fatalf("ORAS fixture is missing; run make setup-oci: %v", err)
	}
	root := t.TempDir()
	keys := filepath.Join(root, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	upstream, err := url.Parse("http://" + address)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Forwarded-Proto", "https")
		proxy.ServeHTTP(w, r)
	}))
	defer proxyServer.Close()
	t.Setenv("REGISTRY_DATA_DIR", filepath.Join(root, "data"))
	t.Setenv("REGISTRY_DATABASE_DRIVER", "sqlite")
	t.Setenv("REGISTRY_MASTER_KEY_FILE", filepath.Join(keys, "master.key"))
	t.Setenv("REGISTRY_CANONICAL_ORIGIN", proxyServer.URL)
	t.Setenv("REGISTRY_ASSET_ORIGIN", "https://assets.example")
	t.Setenv("REGISTRY_TRUSTED_PROXIES", "127.0.0.1")
	t.Setenv("REGISTRY_LISTEN_ADDRESS", address)
	t.Setenv("REGISTRY_EXPERIMENTAL_OCI", "true")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(ctx, []string{"migrate"}, logger); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"init-master-key"}, logger); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	owner := uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (?, 'Synthetic owner', 'now', 'now')`, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_instance_admins (user_id, granted_at) VALUES (?, 'now')`, owner); err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "oci-serve", "OCI serve")
	if err != nil {
		t.Fatal(err)
	}
	repos, err := repositories.New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	if err := repos.EnableFormatCreation(repositories.FormatOCI); err != nil {
		t.Fatal(err)
	}
	repository, err := repos.CreateWithFormat(ctx, owner, workspace.ID, "images", "Images", repositories.FormatOCI)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []repositories.GrantRole{repositories.GrantReader, repositories.GrantPublisher} {
		if _, err := repos.GrantRepositoryRole(ctx, owner, workspace.ID, repository.ID, owner, role); err != nil {
			t.Fatal(err)
		}
	}
	writeToken, err := repos.IssueOCIWriteToken(ctx, owner, workspace.ID, repository.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	readToken, err := repos.IssuePersonalReadToken(ctx, owner, workspace.ID, repository.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stop := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { result <- run(serverCtx, []string{"serve"}, logger) }()
	defer func() {
		stop()
		if err := <-result; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("stop server: %v", err)
		}
	}()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	for {
		response, err := client.Get("http://" + address + "/readyz")
		if err == nil {
			ready := response.StatusCode == http.StatusNoContent
			_ = response.Body.Close()
			if ready {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("server did not become ready")
		case <-time.After(20 * time.Millisecond):
		}
	}
	caPath := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxyServer.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(proxyServer.URL, "https://")
	reference := host + "/" + workspace.ID + "/" + repository.ID + "/team/artifact"

	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	// Larger than a single small request so the client exercises its normal
	// blob upload path.
	payload := bytes.Repeat([]byte("synthetic oci artifact payload\n"), 40000)
	if err := os.WriteFile(filepath.Join(source, "artifact.bin"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	runORAS := func(dir, token string, wantSuccess bool, args ...string) string {
		t.Helper()
		command := exec.CommandContext(ctx, oras, args...)
		command.Dir = dir
		command.Stdin = strings.NewReader(token)
		// No Docker configuration, credential helper or proxy is inherited.
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "DOCKER_CONFIG=" + filepath.Join(root, "empty-docker-config"), "HTTP_PROXY=http://127.0.0.1:9", "HTTPS_PROXY=http://127.0.0.1:9", "NO_PROXY=127.0.0.1,localhost"}
		output, err := command.CombinedOutput()
		text := strings.ReplaceAll(string(output), token, "[redacted]")
		if wantSuccess && err != nil {
			t.Fatalf("oras %s failed: %v output=%s", args[0], err, text)
		}
		if !wantSuccess && err == nil {
			t.Fatalf("oras %s unexpectedly succeeded: %s", args[0], text)
		}
		return text
	}
	credentials := []string{"--ca-file", caPath, "--username", "token", "--password-stdin"}

	runORAS(source, readToken.Bearer, false, append([]string{"push", reference + ":denied", "artifact.bin:application/octet-stream"}, credentials...)...)
	runORAS(source, "prow_"+uuid.NewString()+"."+strings.Repeat("A", 43), false, append([]string{"push", reference + ":denied", "artifact.bin:application/octet-stream"}, credentials...)...)
	runORAS(source, writeToken.Bearer, true, append([]string{"push", reference + ":v1", "artifact.bin:application/octet-stream"}, credentials...)...)

	var tagged, blobs int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_oci_tags WHERE repository_id = ? AND image_name = 'team/artifact'`, repository.ID).Scan(&tagged); err != nil || tagged != 1 {
		t.Fatalf("tags after push: count=%d err=%v", tagged, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_oci_blobs WHERE repository_id = ?`, repository.ID).Scan(&blobs); err != nil || blobs < 2 {
		t.Fatalf("blobs after push: count=%d err=%v", blobs, err)
	}

	destination := filepath.Join(root, "destination")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	runORAS(destination, readToken.Bearer, true, append([]string{"pull", reference + ":v1"}, credentials...)...)
	pulled, err := os.ReadFile(filepath.Join(destination, "artifact.bin"))
	if err != nil || !bytes.Equal(pulled, payload) {
		t.Fatalf("pulled artifact differs: %v", err)
	}
	if tags := runORAS(destination, readToken.Bearer, true, append([]string{"repo", "tags", reference}, credentials...)...); strings.TrimSpace(tags) != "v1" {
		t.Fatalf("tag listing through the client: %q", tags)
	}
	// Retagging through the client and pulling by the new tag.
	runORAS(destination, writeToken.Bearer, true, append([]string{"tag", reference + ":v1", "stable"}, credentials...)...)
	again := filepath.Join(root, "again")
	if err := os.Mkdir(again, 0o700); err != nil {
		t.Fatal(err)
	}
	runORAS(again, readToken.Bearer, true, append([]string{"pull", reference + ":stable"}, credentials...)...)
	if pulled, err := os.ReadFile(filepath.Join(again, "artifact.bin")); err != nil || !bytes.Equal(pulled, payload) {
		t.Fatalf("artifact pulled by the new tag differs: %v", err)
	}
	runORAS(destination, "", false, "pull", "--ca-file", caPath, reference+":v1")
	if entries, err := os.ReadDir(filepath.Join(root, "data", "oci-staging")); err != nil || len(entries) != 0 {
		t.Fatalf("OCI staging not empty after the journey: %d %v", len(entries), err)
	}
}
