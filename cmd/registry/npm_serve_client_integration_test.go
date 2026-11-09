//go:build integration && linux

package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
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

func TestExperimentalNPMServeRealClientJourney(t *testing.T) {
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
	t.Setenv("REGISTRY_EXPERIMENTAL_NPM", "true")
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
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "npm-serve", "npm serve")
	if err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'npm', 'npm', ?, 'now', 'now', 'npm')`, repository, workspace.ID, owner); err != nil {
		t.Fatal(err)
	}
	repos, err := repositories.New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []repositories.GrantRole{repositories.GrantReader, repositories.GrantPublisher} {
		if _, err := repos.GrantRepositoryRole(ctx, owner, workspace.ID, repository, owner, role); err != nil {
			t.Fatal(err)
		}
	}
	writeToken, err := repos.IssueNPMWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	readToken, err := repos.IssuePersonalReadToken(ctx, owner, workspace.ID, repository, time.Hour)
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
	if _, err := repos.GrantNPMTagManager(ctx, owner, workspace.ID, repository, owner); err != nil {
		t.Fatal(err)
	}
	registry := proxyServer.URL + "/npm/" + workspace.ID + "/" + repository + "/"
	parsed, err := url.Parse(registry)
	if err != nil {
		t.Fatal(err)
	}
	writeConfig := filepath.Join(root, "write-npmrc")
	readConfig := filepath.Join(root, "read-npmrc")
	for path, token := range map[string]string{writeConfig: writeToken.Bearer, readConfig: readToken.Bearer} {
		configuration := fmt.Sprintf("registry=%s\n//%s%s:_authToken=%s\naudit=false\nfund=false\nupdate-notifier=false\n", registry, parsed.Host, parsed.Path, token)
		if err := os.WriteFile(path, []byte(configuration), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	project := filepath.Join(root, "package")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"name":"@fixture/serve-package","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "index.js"), []byte("module.exports = 42;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		t.Fatal(err)
	}
	runNPM := func(dir, npmConfig, token string, args ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, npmPath, args...)
		command.Dir = dir
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "NPM_CONFIG_USERCONFIG=" + npmConfig, "NPM_CONFIG_GLOBALCONFIG=/dev/null", "NPM_CONFIG_CACHE=" + filepath.Join(dir, "cache"), "NODE_EXTRA_CA_CERTS=" + caPath, "HTTP_PROXY=http://127.0.0.1:9", "HTTPS_PROXY=http://127.0.0.1:9", "http_proxy=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9", "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost"}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("npm command failed: %v output=%s", err, strings.ReplaceAll(string(output), token, "[redacted]"))
		}
	}
	runNPM(project, writeConfig, writeToken.Bearer, "publish", "--ignore-scripts", "--no-audit", "--json")
	var published int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_npm_packages WHERE repository_id = ? AND name = '@fixture/serve-package'`, repository).Scan(&published); err != nil || published != 1 {
		t.Fatalf("published npm package missing: count=%d err=%v", published, err)
	}
	consumer := filepath.Join(root, "consumer")
	if err := os.Mkdir(consumer, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(consumer, "package.json"), []byte(`{"name":"synthetic-consumer","version":"1.0.0","private":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runNPM(consumer, readConfig, readToken.Bearer, "install", "@fixture/serve-package", "--ignore-scripts", "--no-audit", "--no-fund")
	installed, err := os.ReadFile(filepath.Join(consumer, "node_modules", "@fixture", "serve-package", "index.js"))
	if err != nil || string(installed) != "module.exports = 42;\n" {
		t.Fatalf("installed npm package differs: %v", err)
	}
}
