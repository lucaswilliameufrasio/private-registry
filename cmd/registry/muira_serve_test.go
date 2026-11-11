//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestServeMuiraSignInRequiresOptIn runs the real serve command: the Muira
// routes are absent by default and, once configured, the start route redirects
// to the discovered authorize endpoint with PKCE, state and nonce. The provider
// is a local synthetic one; no real Muira is contacted.
func TestServeMuiraSignInRequiresOptIn(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/oauth/jwks.json", "authorization_endpoint": issuer + "/oauth/authorize", "token_endpoint": issuer + "/oauth/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/oauth/jwks.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "fixture", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	providerHost, _, err := net.SplitHostPort(strings.TrimPrefix(issuer, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			root := t.TempDir()
			keys := filepath.Join(root, "keys")
			if err := os.Mkdir(keys, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("REGISTRY_DATA_DIR", filepath.Join(root, "data"))
			t.Setenv("REGISTRY_DATABASE_DRIVER", "sqlite")
			t.Setenv("REGISTRY_MASTER_KEY_FILE", filepath.Join(keys, "master.key"))
			t.Setenv("REGISTRY_CANONICAL_ORIGIN", "https://registry.example")
			t.Setenv("REGISTRY_ASSET_ORIGIN", "https://assets.example")
			t.Setenv("REGISTRY_TRUSTED_PROXIES", "127.0.0.1")
			if enabled {
				secretFile := filepath.Join(keys, "muira-client-secret")
				caFile := filepath.Join(keys, "muira-ca.pem")
				if err := os.WriteFile(secretFile, []byte("synthetic-client-secret\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw}), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("REGISTRY_MUIRA_ENABLED", "true")
				t.Setenv("REGISTRY_MUIRA_ISSUER", issuer)
				t.Setenv("REGISTRY_MUIRA_CLIENT_ID", "synthetic-registry")
				t.Setenv("REGISTRY_MUIRA_CLIENT_SECRET_FILE", secretFile)
				t.Setenv("REGISTRY_MUIRA_CA_FILE", caFile)
				t.Setenv("REGISTRY_MUIRA_ALLOWED_NETWORKS", providerHost+"/32")
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			t.Setenv("REGISTRY_LISTEN_ADDRESS", address)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			if err := run(ctx, []string{"migrate"}, logger); err != nil {
				t.Fatal(err)
			}
			if err := run(ctx, []string{"init-master-key"}, logger); err != nil {
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
			client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
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
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/api/v1/auth/muira/start", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Host = "registry.example"
			request.Header.Set("X-Forwarded-Proto", "https")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if !enabled {
				if response.StatusCode != http.StatusNotFound {
					t.Fatalf("Muira route exists without opt-in: %d", response.StatusCode)
				}
				return
			}
			location := response.Header.Get("Location")
			if response.StatusCode != http.StatusFound || !strings.HasPrefix(location, issuer+"/oauth/authorize?") || !strings.Contains(location, "code_challenge_method=S256") || !strings.Contains(location, "redirect_uri=https%3A%2F%2Fregistry.example%2Fapi%2Fv1%2Fauth%2Fmuira%2Fcallback") || !strings.Contains(location, "nonce=") || !strings.Contains(location, "state=") {
				t.Fatalf("Muira start did not redirect per contract: status=%d location=%s", response.StatusCode, location)
			}
			if strings.Contains(location, "synthetic-client-secret") {
				t.Fatal("client secret leaked into the browser redirect")
			}
		})
	}
}

func TestServeRefusesUnreachableMuira(t *testing.T) {
	root := t.TempDir()
	keys := filepath.Join(root, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(keys, "muira-client-secret")
	if err := os.WriteFile(secretFile, []byte("synthetic-client-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGISTRY_DATA_DIR", filepath.Join(root, "data"))
	t.Setenv("REGISTRY_DATABASE_DRIVER", "sqlite")
	t.Setenv("REGISTRY_MASTER_KEY_FILE", filepath.Join(keys, "master.key"))
	t.Setenv("REGISTRY_CANONICAL_ORIGIN", "https://registry.example")
	t.Setenv("REGISTRY_ASSET_ORIGIN", "https://assets.example")
	t.Setenv("REGISTRY_TRUSTED_PROXIES", "127.0.0.1")
	t.Setenv("REGISTRY_LISTEN_ADDRESS", "127.0.0.1:18089")
	t.Setenv("REGISTRY_MUIRA_ENABLED", "true")
	// The issuer is a literal address outside the allowed networks, so the
	// restricted client refuses to dial it.
	t.Setenv("REGISTRY_MUIRA_ISSUER", "https://127.0.0.1:9")
	t.Setenv("REGISTRY_MUIRA_CLIENT_ID", "synthetic-registry")
	t.Setenv("REGISTRY_MUIRA_CLIENT_SECRET_FILE", secretFile)
	t.Setenv("REGISTRY_MUIRA_ALLOWED_NETWORKS", "192.0.2.0/24")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(ctx, []string{"migrate"}, logger); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"init-master-key"}, logger); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"serve"}, logger); err == nil || strings.Contains(err.Error(), "synthetic-client-secret") {
		t.Fatalf("serve started with an unreachable Muira or leaked the secret: %v", err)
	}
}
