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

func TestExperimentalCargoServeRealClientJourney(t *testing.T) {
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
	t.Setenv("REGISTRY_EXPERIMENTAL_CARGO", "true")
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
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "cargo-serve", "Cargo serve")
	if err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'cargo', 'Cargo', ?, 'now', 'now', 'cargo')`, repository, workspace.ID, owner); err != nil {
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
	writeToken, err := repos.IssueCargoWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
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
	registry := proxyServer.URL + "/cargo/" + workspace.ID + "/" + repository
	cargoHome := filepath.Join(root, "cargo-home")
	if err := os.Mkdir(cargoHome, 0o700); err != nil {
		t.Fatal(err)
	}
	// The real registryctl provider, built from this checkout, hands Cargo the
	// read token for index access and the write token for publication.
	providerPath := filepath.Join(root, "registryctl")
	if output, err := exec.CommandContext(ctx, "go", "build", "-o", providerPath, "private-registry/cmd/registryctl").CombinedOutput(); err != nil {
		t.Fatalf("build registryctl: %v %s", err, output)
	}
	readTokenFile := filepath.Join(root, "cargo-read-token")
	writeTokenFile := filepath.Join(root, "cargo-write-token")
	for path, token := range map[string]string{readTokenFile: readToken.Bearer, writeTokenFile: writeToken.Bearer} {
		if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	index := "sparse+" + registry + "/index/"
	configuration := fmt.Sprintf("[credential-alias]\nfixture = [%q, \"-index\", %q, \"-read-token-file\", %q, \"-write-token-file\", %q]\n[registries.private]\nindex = %q\ncredential-provider = \"fixture\"\n", providerPath, index, readTokenFile, writeTokenFile, index)
	if err := os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "crate")
	if err := os.MkdirAll(filepath.Join(project, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "Cargo.toml"), []byte("[package]\nname = \"serve_cargo_fixture\"\nversion = \"1.0.0\"\nedition = \"2021\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "src", "lib.rs"), []byte("pub fn value() -> u8 { 7 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sysrootCmd := exec.CommandContext(ctx, "rustup", "run", "1.99.0-x86_64-unknown-linux-gnu", "rustc", "--print", "sysroot")
	sysroot, err := sysrootCmd.Output()
	if err != nil {
		t.Fatal("Rust integration toolchain unavailable")
	}
	bin := filepath.Join(strings.TrimSpace(string(sysroot)), "bin")
	runCargo := func(args ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, filepath.Join(bin, "cargo"), args...)
		command.Dir = root
		command.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + root, "CARGO_HOME=" + cargoHome, "CARGO_TARGET_DIR=" + filepath.Join(root, "target"), "CARGO_HTTP_CAINFO=" + caPath, "CARGO_HTTP_TIMEOUT=20", "CARGO_HTTP_MULTIPLEXING=false", "CARGO_NET_RETRY=0", "CARGO_TERM_COLOR=never", "HTTP_PROXY=http://127.0.0.1:9", "HTTPS_PROXY=http://127.0.0.1:9", "http_proxy=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9", "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost"}
		if output, err := command.CombinedOutput(); err != nil {
			safe := strings.ReplaceAll(string(output), writeToken.Bearer, "[redacted]")
			safe = strings.ReplaceAll(safe, readToken.Bearer, "[redacted]")
			t.Fatalf("Cargo command failed: %v output=%s", err, safe)
		}
	}
	runCargo("publish", "--no-verify", "--allow-dirty", "--registry", "private", "--manifest-path", filepath.Join(project, "Cargo.toml"))
	var published int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_cargo_packages WHERE repository_id = ? AND name = 'serve_cargo_fixture'`, repository).Scan(&published); err != nil || published != 1 {
		t.Fatalf("published Cargo package missing: count=%d err=%v", published, err)
	}
	parent := filepath.Join(root, "parent")
	if err := os.MkdirAll(filepath.Join(parent, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	parentManifest := "[package]\nname = \"serve_cargo_parent\"\nversion = \"1.0.0\"\nedition = \"2021\"\n[dependencies]\nserve_cargo_fixture = { version = \"=1.0.0\", registry = \"private\" }\n"
	if err := os.WriteFile(filepath.Join(parent, "Cargo.toml"), []byte(parentManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "src", "lib.rs"), []byte("pub fn value() -> u8 { serve_cargo_fixture::value() }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCargo("publish", "--no-verify", "--allow-dirty", "--registry", "private", "--manifest-path", filepath.Join(parent, "Cargo.toml"))
	consumer := filepath.Join(root, "consumer")
	if err := os.MkdirAll(filepath.Join(consumer, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(consumer, "Cargo.toml"), []byte("[package]\nname = \"serve_consumer\"\nversion = \"1.0.0\"\nedition = \"2021\"\n[dependencies]\nserve_cargo_parent = { version = \"=1.0.0\", registry = \"private\" }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(consumer, "src", "lib.rs"), []byte("pub fn value() -> u8 { serve_cargo_parent::value() }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCargo("check", "--manifest-path", filepath.Join(consumer, "Cargo.toml"))
	lock, err := os.ReadFile(filepath.Join(consumer, "Cargo.lock"))
	if err != nil || !strings.Contains(string(lock), "serve_cargo_fixture") || !strings.Contains(string(lock), "serve_cargo_parent") {
		t.Fatalf("published Cargo dependency missing from lockfile: %v", err)
	}
}
