//go:build integration && linux

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
	"private-registry/internal/password"
)

const mailpitBinary = "/tmp/opencode/private-registry-mailpit/mailpit"

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

type mailpit struct {
	api    string
	client *http.Client
}

func startMailpit(t *testing.T, ctx context.Context) (*mailpit, string) {
	t.Helper()
	if _, err := os.Stat(mailpitBinary); err != nil {
		t.Fatalf("Mailpit is missing; run make setup-mailpit: %v", err)
	}
	smtpAddress, httpAddress := freeLoopbackAddress(t), freeLoopbackAddress(t)
	command := exec.CommandContext(ctx, mailpitBinary, "--smtp", smtpAddress, "--listen", httpAddress, "--database", filepath.Join(t.TempDir(), "mailpit.db"), "--disable-version-check", "--quiet")
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
		if t.Failed() {
			t.Logf("Mailpit output:\n%s", output.String())
		}
	})
	box := &mailpit{api: "http://" + httpAddress, client: &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}}
	for {
		response, err := box.client.Get(box.api + "/api/v1/messages")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return box, smtpAddress
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("Mailpit did not start")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

type mailpitMessage struct {
	ID      string `json:"ID"`
	Subject string `json:"Subject"`
	To      []struct {
		Address string `json:"Address"`
	} `json:"To"`
}

// waitFor returns the first message to recipient whose subject contains
// subject, once Mailpit has received it.
func (m *mailpit) waitFor(t *testing.T, ctx context.Context, recipient, subject string) (mailpitMessage, string, string) {
	t.Helper()
	for {
		response, err := m.client.Get(m.api + "/api/v1/messages")
		if err == nil {
			var listing struct {
				Messages []mailpitMessage `json:"messages"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&listing)
			_ = response.Body.Close()
			if decodeErr == nil {
				for _, message := range listing.Messages {
					if len(message.To) == 1 && message.To[0].Address == recipient && strings.Contains(message.Subject, subject) {
						detail, err := m.client.Get(m.api + "/api/v1/message/" + url.PathEscape(message.ID))
						if err != nil {
							t.Fatal(err)
						}
						var body struct {
							Text string `json:"Text"`
							HTML string `json:"HTML"`
						}
						err = json.NewDecoder(detail.Body).Decode(&body)
						_ = detail.Body.Close()
						if err != nil {
							t.Fatal(err)
						}
						return message, body.Text, body.HTML
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("no email %q reached %s", subject, recipient)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// TestServeDeliversRecoveryEmailThroughMailpit runs the real serve command
// with SMTP to a local Mailpit: a person asks for a recovery link, receives
// it, sets a new password with it and then receives the security notice.
func TestServeDeliversRecoveryEmailThroughMailpit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	box, smtpAddress := startMailpit(t, ctx)

	root := t.TempDir()
	keys := filepath.Join(root, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(root, "data")
	address := freeLoopbackAddress(t)
	for key, value := range map[string]string{
		"REGISTRY_DATA_DIR":               dataDir,
		"REGISTRY_DATABASE_DRIVER":        "sqlite",
		"REGISTRY_MASTER_KEY_FILE":        filepath.Join(keys, "master.key"),
		"REGISTRY_CANONICAL_ORIGIN":       "https://registry.example",
		"REGISTRY_ASSET_ORIGIN":           "https://assets.example",
		"REGISTRY_TRUSTED_PROXIES":        "127.0.0.1",
		"REGISTRY_LISTEN_ADDRESS":         address,
		"REGISTRY_EMAIL_PROVIDER":         "smtp",
		"REGISTRY_EMAIL_SMTP_ADDRESS":     smtpAddress,
		"REGISTRY_EMAIL_SMTP_SECURITY":    "none",
		"REGISTRY_EMAIL_FROM":             "Registry <registry@registry.example>",
		"REGISTRY_EMAIL_ALLOWED_NETWORKS": "127.0.0.1/32",
	} {
		t.Setenv(key, value)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(ctx, []string{"migrate"}, logger); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"init-master-key"}, logger); err != nil {
		t.Fatal(err)
	}
	seedConfirmedAccount(t, ctx, filepath.Join(dataDir, "registry.sqlite"), "ana", "ana@example.com")

	serverCtx, stop := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { result <- run(serverCtx, []string{"serve"}, logger) }()
	defer func() {
		stop()
		if err := <-result; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("stop server: %v", err)
		}
	}()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
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
		case err := <-result:
			t.Fatalf("server stopped during startup: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	post := func(path string, body any) int {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "registry.example"
		request.Header.Set("Origin", "https://registry.example")
		request.Header.Set("X-Forwarded-Proto", "https")
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		return response.StatusCode
	}

	if status := post("/api/v1/auth/recovery/request", map[string]string{"login_name": "ana"}); status != http.StatusAccepted {
		t.Fatalf("recovery request: %d", status)
	}
	if status := post("/api/v1/auth/recovery/request", map[string]string{"login_name": "nobody"}); status != http.StatusAccepted {
		t.Fatalf("unknown login must look the same: %d", status)
	}
	_, text, html := box.waitFor(t, ctx, "ana@example.com", "Recuperação")
	link := regexp.MustCompile(`https://registry\.example/#/recover\?token=[A-Za-z0-9%._-]+`).FindString(text)
	if link == "" || !strings.Contains(html, "Definir nova senha") {
		t.Fatalf("recovery email without a link:\n%s", text)
	}
	token, err := url.QueryUnescape(strings.TrimPrefix(link, "https://registry.example/#/recover?token="))
	if err != nil {
		t.Fatal(err)
	}
	if status := post("/api/v1/auth/recovery", map[string]string{"token": token, "password": "a-new-synthetic-password-1"}); status != http.StatusNoContent {
		t.Fatalf("complete recovery: %d", status)
	}
	if status := post("/api/v1/auth/recovery", map[string]string{"token": token, "password": "a-new-synthetic-password-2"}); status != http.StatusNotFound {
		t.Fatalf("recovery link reused: %d", status)
	}
	_, notice, _ := box.waitFor(t, ctx, "ana@example.com", "Aviso de segurança")
	if !strings.Contains(notice, "senha redefinida") {
		t.Fatalf("unexpected notice:\n%s", notice)
	}

	// Only those two messages were sent, and the database holds no plaintext
	// recipient or link.
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "registry.sqlite")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_jobs WHERE kind = 'email.send' AND (payload LIKE '%ana@%' OR payload LIKE '%prrst_%')`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("plaintext email payloads: %d %v", count, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_jobs WHERE kind = 'email.send' AND status = 'succeeded'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("delivered emails: %d %v", count, err)
	}
}

func seedConfirmedAccount(t *testing.T, ctx context.Context, path, login, address string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hash, err := password.Hash([]byte("synthetic-email-password-never-reuse"))
	if err != nil {
		t.Fatal(err)
	}
	userID := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_users (user_id, display_name, email, email_verified, status, created_at, updated_at) VALUES (?, ?, ?, 1, 'active', ?, ?)`, userID, "Ana", address, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_local_credentials (user_id, login_name, password_hash, created_at, updated_at, password_changed_at) VALUES (?, ?, ?, ?, ?, ?)`, userID, login, hash, now, now, now); err != nil {
		t.Fatal(err)
	}
}
