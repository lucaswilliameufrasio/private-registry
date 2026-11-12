//go:build integration && linux

package main

import (
	"context"
	"crypto/tls"
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
	"strconv"
	"strings"
	"testing"
	"time"

	"private-registry/internal/bootstrap"
	"private-registry/internal/config"
	"private-registry/internal/database"
)

// TestWebInterfaceInARealBrowser runs the serve command behind TLS and drives
// the web interface with headless Chromium, including a passkey through
// Chromium's virtual authenticator. It runs when BROWSER_TEST_CHROMIUM points
// to a Chromium or chrome-headless-shell binary.
func TestWebInterfaceInARealBrowser(t *testing.T) {
	chromium := os.Getenv("BROWSER_TEST_CHROMIUM")
	if chromium == "" {
		t.Skip("set BROWSER_TEST_CHROMIUM to a Chromium binary to run the browser journey")
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
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Forwarded-Proto", "https")
		proxy.ServeHTTP(w, r)
	}))
	front.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	front.StartTLS()
	defer front.Close()
	// *.localhost resolves to loopback in Chromium and is a domain, which
	// WebAuthn requires.
	_, frontPort, _ := net.SplitHostPort(front.Listener.Addr().String())
	origin := "https://registry.localhost:" + frontPort
	t.Setenv("REGISTRY_DATA_DIR", filepath.Join(root, "data"))
	t.Setenv("REGISTRY_DATABASE_DRIVER", "sqlite")
	t.Setenv("REGISTRY_MASTER_KEY_FILE", filepath.Join(keys, "master.key"))
	t.Setenv("REGISTRY_CANONICAL_ORIGIN", origin)
	t.Setenv("REGISTRY_ASSET_ORIGIN", "https://assets.localhost:"+frontPort)
	t.Setenv("REGISTRY_TRUSTED_PROXIES", "127.0.0.1")
	t.Setenv("REGISTRY_LISTEN_ADDRESS", address)
	t.Setenv("REGISTRY_EXPERIMENTAL_NPM", "true")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	box, smtpAddress := startMailpit(t, ctx)
	t.Setenv("REGISTRY_EMAIL_PROVIDER", "smtp")
	t.Setenv("REGISTRY_EMAIL_SMTP_ADDRESS", smtpAddress)
	t.Setenv("REGISTRY_EMAIL_SMTP_SECURITY", "none")
	t.Setenv("REGISTRY_EMAIL_FROM", "Registry <registry@registry.example>")
	t.Setenv("REGISTRY_EMAIL_ALLOWED_NETWORKS", "127.0.0.1/32")
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
	const password = "synthetic-browser-password-never-reuse"
	if _, err := bootstrap.CreateFirstAdmin(ctx, db, config.SQLite, bootstrap.AdminInput{LoginName: "browser.admin", DisplayName: "Browser Admin", Email: "browser@example.invalid", Password: []byte(password), OperatorLabel: "browser-test"}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	serverCtx, stop := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { result <- run(serverCtx, []string{"serve"}, logger) }()
	defer func() {
		stop()
		if err := <-result; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("stop server: %v", err)
		}
	}()
	for {
		response, err := (&http.Client{Timeout: time.Second}).Get("http://" + address + "/readyz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("server did not become ready")
		case <-time.After(20 * time.Millisecond):
		}
	}
	debugListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, debugPort, _ := net.SplitHostPort(debugListener.Addr().String())
	_ = debugListener.Close()
	browser := exec.CommandContext(ctx, chromium, "--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run", "--ignore-certificate-errors",
		"--host-resolver-rules=MAP registry.localhost 127.0.0.1,MAP assets.localhost 127.0.0.1", "--remote-debugging-port="+debugPort, "--user-data-dir="+filepath.Join(root, "chromium"), "about:blank")
	browser.Stderr = io.Discard
	if err := browser.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = browser.Process.Kill()
		_ = browser.Wait()
	}()
	for {
		response, err := (&http.Client{Timeout: time.Second}).Get("http://127.0.0.1:" + debugPort + "/json/version")
		if err == nil {
			_ = response.Body.Close()
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("Chromium did not start")
		case <-time.After(50 * time.Millisecond):
		}
	}
	script, err := filepath.Abs("testdata/browser_journey.mjs")
	if err != nil {
		t.Fatal(err)
	}
	journey := exec.CommandContext(ctx, "node", script, debugPort, origin, "browser.admin", password, box.api)
	output, err := journey.CombinedOutput()
	t.Logf("browser journey output:\n%s", output)
	if err != nil || !strings.Contains(string(output), "browser journey passed") {
		t.Fatalf("browser journey failed: %v", err)
	}
	_ = strconv.Itoa
}
