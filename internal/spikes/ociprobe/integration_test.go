//go:build integration

package ociprobe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const toolsRoot = "/tmp/opencode/private-registry-oci-tools"
const repository = "fixture/oci/artifact"

func TestDistributionScopesAndNativeRevocationGap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for _, tool := range []string{"registry", "oras"} {
		if _, err := os.Stat(filepath.Join(toolsRoot, tool)); err != nil {
			t.Fatal("real OCI tools missing; run make setup-oci:", err)
		}
	}
	// Short path avoids Linux's 108-byte Unix socket pathname limit.
	directory, err := os.MkdirTemp("/tmp/opencode", "oci-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(directory); err != nil { // Only owned synthetic files.
			t.Error(err)
		}
	}()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OCI fixture only"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(directory, "trust.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(der)}))
	if err != nil {
		t.Fatal(err)
	}
	token := func(subject, audience, issuer, name string, actions []string, expires time.Time) string {
		t.Helper()
		access := map[string]any{"access": []map[string]any{{"type": "repository", "name": name, "actions": actions}}}
		raw, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: issuer, Subject: subject,
			Audience: jwt.Audience{audience}, IssuedAt: jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Second)), Expiry: jwt.NewNumericDate(expires)}).Claims(access).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var revoked atomic.Bool
	var enforceCurrent atomic.Bool
	socket := filepath.Join(directory, "registry.sock")
	upstream, _ := url.Parse("http://registry.internal")
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	proxy.Transport = transport
	// First characterize native auth, then enable the minimal experimental
	// current-account gate. Neither mode is a complete production gateway.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			prefix, raw, ok := strings.Cut(r.Header.Get("Authorization"), " ")
			if enforceCurrent.Load() && ok && strings.EqualFold(prefix, "Bearer") {
				parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
				var claims jwt.Claims
				if err == nil {
					err = parsed.Claims(&key.PublicKey, &claims)
				}
				if err == nil {
					err = claims.ValidateWithLeeway(jwt.Expected{Issuer: "fixture-issuer", AnyAudience: jwt.Audience{"fixture-registry"}, Time: time.Now()}, 0)
				}
				if err != nil {
					http.Error(w, "invalid fixture token", http.StatusUnauthorized)
					return
				}
				if claims.Subject == "publisher" && revoked.Load() {
					http.Error(w, "fixture account revoked", http.StatusForbidden)
					return
				}
			}
			proxy.ServeHTTP(w, r)
			return
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != "publisher" || password != "fixture-only" || revoked.Load() {
			http.Error(w, "fixture credentials unavailable", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("service") != "fixture-registry" {
			http.Error(w, "wrong service", http.StatusBadRequest)
			return
		}
		var actions []string
		for _, scope := range r.URL.Query()["scope"] {
			parts := strings.Split(scope, ":")
			if len(parts) != 3 || parts[0] != "repository" || parts[1] != repository {
				http.Error(w, "fixture scope denied", http.StatusForbidden)
				return
			}
			for _, action := range strings.Split(parts[2], ",") {
				if action != "pull" && action != "push" {
					http.Error(w, "fixture action denied", http.StatusForbidden)
					return
				}
				actions = append(actions, action)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"token": token(user, "fixture-registry", "fixture-issuer", repository, actions, time.Now().Add(5*time.Minute)), "expires_in": 300})
	}))
	defer server.Close()
	config := fmt.Sprintf(`version: 0.1
log:
  level: error
storage:
  filesystem:
    rootdirectory: %s
  redirect:
    disable: true
http:
  net: unix
  addr: %s
  host: %s
  secret: synthetic-fixture-only
auth:
  token:
    realm: %s/token
    service: fixture-registry
    issuer: fixture-issuer
    rootcertbundle: %s
    signingalgorithms: [ES256]
`, filepath.Join(directory, "storage"), socket, server.URL, server.URL, certPath)
	configPath := filepath.Join(directory, "config.yml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, filepath.Join(toolsRoot, "registry"), "serve", configPath)
	command.WaitDelay = 2 * time.Second
	// Do not inherit operator storage, cloud or telemetry configuration.
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "GOMAXPROCS=2", "GOMEMLIMIT=256MiB", "OTEL_SDK_DISABLED=true"}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Signal(os.Interrupt); _ = command.Process.Kill(); _ = command.Wait() }()
	client := &http.Client{Timeout: 5 * time.Second}
	for {
		if _, err := os.Stat(socket); err == nil {
			if err := os.Chmod(socket, 0o600); err != nil {
				t.Fatal(err)
			}
			break
		}
		if err := ctx.Err(); err != nil {
			t.Fatal("registry Unix socket never became ready:", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	authFile := filepath.Join(directory, "oras-auth.json")
	oras := func(input string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, filepath.Join(toolsRoot, "oras"), args...)
		cmd.Dir = directory
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + directory, "GOMAXPROCS=2"}
		cmd.Stdin = strings.NewReader(input)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("ORAS fixture operation failed: %v %s", err, output)
		}
		return string(output)
	}
	host := strings.TrimPrefix(server.URL, "http://")
	oras("fixture-only\n", "login", "--plain-http", "--registry-config", authFile, "--username", "publisher", "--password-stdin", host)
	payload := []byte("synthetic OCI artifact; never execute")
	if err := os.WriteFile(filepath.Join(directory, "payload.txt"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	oras("", "push", "--plain-http", "--registry-config", authFile, host+"/"+repository+":v1", "payload.txt:application/octet-stream")
	pulled := filepath.Join(directory, "pulled")
	oras("", "pull", "--plain-http", "--registry-config", authFile, "--output", pulled, host+"/"+repository+":v1")
	actual, err := os.ReadFile(filepath.Join(pulled, "payload.txt"))
	if err != nil || !bytes.Equal(actual, payload) {
		t.Fatal("real ORAS pull differs from pushed artifact:", err)
	}
	request := func(method, path, raw string) int {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if raw != "" {
			r.Header.Set("Authorization", "Bearer "+raw)
		}
		r.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}
	manifest := "/v2/" + repository + "/manifests/v1"
	if status := request("GET", manifest, ""); status != 401 {
		t.Fatalf("anonymous private pull accepted: %d", status)
	}
	readOnly := token("reader", "fixture-registry", "fixture-issuer", repository, []string{"pull"}, time.Now().Add(time.Minute))
	if status := request("HEAD", manifest, readOnly); status != 200 {
		t.Fatalf("scoped HEAD denied: %d", status)
	}
	if status := request("POST", "/v2/"+repository+"/blobs/uploads/", readOnly); status != 401 {
		t.Fatalf("pull-only token allowed upload: %d", status)
	}
	for _, raw := range []string{
		token("reader", "wrong", "fixture-issuer", repository, []string{"pull"}, time.Now().Add(time.Minute)),
		token("reader", "fixture-registry", "wrong", repository, []string{"pull"}, time.Now().Add(time.Minute)),
		token("reader", "fixture-registry", "fixture-issuer", "another/workspace/image", []string{"pull"}, time.Now().Add(time.Minute)),
		token("reader", "fixture-registry", "fixture-issuer", repository, []string{"pull"}, time.Now().Add(-2*time.Minute)),
		"invalid-token",
	} {
		if status := request("GET", manifest, raw); status != 401 {
			t.Fatalf("invalid/scopeless token accepted: %d", status)
		}
	}
	cached := token("publisher", "fixture-registry", "fixture-issuer", repository, []string{"pull", "push"}, time.Now().Add(5*time.Minute))
	start, err := http.NewRequestWithContext(ctx, "POST", server.URL+"/v2/"+repository+"/blobs/uploads/", nil)
	if err != nil {
		t.Fatal(err)
	}
	start.Header.Set("Authorization", "Bearer "+cached)
	upload, err := client.Do(start)
	if err != nil {
		t.Fatal(err)
	}
	_ = upload.Body.Close()
	if upload.StatusCode != 202 {
		t.Fatalf("active upload was not started: %d", upload.StatusCode)
	}
	location, err := url.Parse(upload.Header.Get("Location"))
	if err != nil || location.Host != host {
		t.Fatal("upload location escaped the fixture gateway")
	}
	values := location.Query()
	values.Set("digest", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	location.RawQuery = values.Encode()
	revoked.Store(true)
	newToken, err := http.NewRequestWithContext(ctx, "GET", server.URL+"/token?service=fixture-registry", nil)
	if err != nil {
		t.Fatal(err)
	}
	newToken.SetBasicAuth("publisher", "fixture-only")
	issuance, err := client.Do(newToken)
	if err != nil {
		t.Fatal(err)
	}
	_ = issuance.Body.Close()
	if issuance.StatusCode != 401 {
		t.Fatal("revoked fixture account still obtained new tokens")
	}
	// Known native gap: blocking future issuance does not revoke cached JWTs.
	if status := request("GET", manifest, cached); status != 200 {
		t.Fatalf("native revocation characterization changed: %d", status)
	}
	enforceCurrent.Store(true)
	if status := request("GET", manifest, cached); status != 403 {
		t.Fatalf("current-account gate did not deny cached JWT: %d", status)
	}
	if status := request("PUT", location.RequestURI(), cached); status != 403 {
		t.Fatalf("revoked account finalized an active upload: %d", status)
	}
	lowercase, err := http.NewRequestWithContext(ctx, "GET", server.URL+manifest, nil)
	if err != nil {
		t.Fatal(err)
	}
	lowercase.Header.Set("Authorization", "bearer "+cached)
	lowercaseResponse, err := client.Do(lowercase)
	if err != nil {
		t.Fatal(err)
	}
	_ = lowercaseResponse.Body.Close()
	if lowercaseResponse.StatusCode != 403 {
		t.Fatal("lowercase bearer bypassed current-account revocation")
	}
	if status := request("HEAD", manifest, readOnly); status != 200 {
		t.Fatalf("unaffected reader lost access: %d", status)
	}
	t.Log("ORAS 1.3.4/Distribution 3.1.2: push/pull and token boundaries valid; native cached JWT survives issuer revocation; experimental current-account gate denies cached pull/upload completion without blocking unaffected reader")
}
