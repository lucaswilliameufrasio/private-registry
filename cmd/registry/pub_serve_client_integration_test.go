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

func TestExperimentalPubServeRealDartJourney(t *testing.T) {
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
	t.Setenv("REGISTRY_EXPERIMENTAL_PUB", "true")
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
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "dart-serve", "Dart serve")
	if err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'pub', 'Pub', ?, 'now', 'now', 'pub')`, repository, workspace.ID, owner); err != nil {
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
	writeToken, err := repos.IssuePubWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
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
	registry := proxyServer.URL + "/pub/" + workspace.ID + "/" + repository
	publisher := filepath.Join(root, "publisher")
	if err := os.MkdirAll(filepath.Join(publisher, "lib"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf("name: serve_fixture\nversion: 1.0.0\ndescription: Synthetic package.\npublish_to: %s\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\n", registry)
	for name, contents := range map[string]string{"pubspec.yaml": manifest, "lib/serve_fixture.dart": "String value() => 'fixture';\n", "LICENSE": "Synthetic test fixture.\n"} {
		if err := os.WriteFile(filepath.Join(publisher, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	consumer := filepath.Join(root, "consumer")
	if err := os.Mkdir(consumer, 0o700); err != nil {
		t.Fatal(err)
	}
	consumerManifest := fmt.Sprintf("name: serve_consumer\npublish_to: none\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n  serve_fixture:\n    hosted:\n      name: serve_fixture\n      url: %s\n    version: ^1.0.0\n", registry)
	if err := os.WriteFile(filepath.Join(consumer, "pubspec.yaml"), []byte(consumerManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	dart := os.Getenv("PUB_TEST_DART_BIN")
	if dart == "" {
		dart, err = exec.LookPath("dart")
		if err != nil {
			t.Fatal(err)
		}
	}
	runtime := filepath.Join(filepath.Dir(dart), "dartaotruntime")
	snapshot := filepath.Join(filepath.Dir(dart), "snapshots", "dartdev_aot.dart.snapshot")
	runDart := func(dir, token string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, runtime, append([]string{"--root-certs-file=" + caPath, snapshot}, args...)...)
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(root, "home"), "XDG_CONFIG_HOME=" + filepath.Join(dir, "config"), "PUB_CACHE=" + filepath.Join(dir, "cache"), "PUB_ENVIRONMENT=bot", "CI=true", "SSL_CERT_FILE=" + caPath, "PUB_FIXTURE_TOKEN=" + token, "HTTP_PROXY=http://127.0.0.1:9", "HTTPS_PROXY=http://127.0.0.1:9", "ALL_PROXY=http://127.0.0.1:9", "http_proxy=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9", "all_proxy=http://127.0.0.1:9", "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost"}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Dart command failed: %v output=%s", err, strings.ReplaceAll(string(output), token, "[redacted]"))
		}
	}
	runDart(publisher, writeToken.Bearer, "pub", "token", "add", "--env-var=PUB_FIXTURE_TOKEN", registry)
	runDart(publisher, writeToken.Bearer, "pub", "publish", "--force")
	var published int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_pub_packages WHERE repository_id = ? AND name = 'serve_fixture'`, repository).Scan(&published); err != nil || published != 1 {
		t.Fatalf("published package missing: count=%d err=%v", published, err)
	}
	runDart(consumer, readToken.Bearer, "pub", "token", "add", "--env-var=PUB_FIXTURE_TOKEN", registry)
	runDart(consumer, readToken.Bearer, "pub", "get")
	lock, err := os.ReadFile(filepath.Join(consumer, "pubspec.lock"))
	if err != nil || !strings.Contains(string(lock), "serve_fixture") {
		t.Fatalf("published dependency missing from lockfile: %v", err)
	}
}
