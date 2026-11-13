package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/oci"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
	"private-registry/internal/trustedpub"
)

// fakeGitHubOIDC serves discovery and JWKS like token.actions.githubusercontent.com.
type fakeGitHubOIDC struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newFakeGitHubOIDC(t *testing.T) *fakeGitHubOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeGitHubOIDC{key: key}
	fake.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := fake.server.URL
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/.well-known/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"id_token"}, "subject_types_supported": []string{"public"}})
		case "/.well-known/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "ci", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeGitHubOIDC) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	base := map[string]any{"iss": f.server.URL, "aud": authTestOrigin, "sub": "repo:octo/app:ref:refs/heads/main", "repository": "octo/app", "repository_id": "4242", "ref": "refs/heads/main", "event_name": "push", "jti": uuid.NewString(), "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix()}
	for key, value := range claims {
		if value == nil {
			delete(base, key)
			continue
		}
		base[key] = value
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"ci","typ":"JWT"}`))
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	body := header + "." + base64.RawURLEncoding.EncodeToString(encoded)
	digest := sha256.Sum256([]byte(body))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return body + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestServiceAccountsAndTrustedPublishing(t *testing.T) {
	f := newOCIHTTPFixture(t)
	ctx := context.Background()
	github := newFakeGitHubOIDC(t)
	client := github.server.Client()
	client.Timeout = 5 * time.Second
	trusted, err := trustedpub.New(f.db, "sqlite", f.repositoryService, github.server.URL, authTestOrigin, client)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewFileSystem(t.TempDir() + "/objects")
	if err != nil {
		t.Fatal(err)
	}
	service, err := oci.New(f.db, "sqlite", f.repositoryService, store, oci.Options{StagingDirectory: t.TempDir() + "/oci", MaxBlobBytes: 1 << 20, MaxUploads: 4})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewHealth(f.db), f.service, f.workspaceService, f.repositoryService, f.artifactService, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin, OCI: service, TrustedPublishing: trusted})
	if err != nil {
		t.Fatal(err)
	}
	f.handler = handler
	admin := muiraAdminMFACookies(t, handler)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		return authHTTPRequestWithCookies(handler, method, path, body, authTestOrigin, "registry.example", admin, admin[csrfCookieName].Value)
	}
	created := call(http.MethodPost, "/api/v1/workspaces/"+f.workspace+"/service-accounts", `{"description":"release pipeline"}`)
	var account serviceAccountResponse
	if err := json.Unmarshal(created.Body.Bytes(), &account); err != nil || created.Code != http.StatusCreated || account.UserID == "" {
		t.Fatalf("create service account: %d %s", created.Code, created.Body.String())
	}
	// A service account cannot sign in and can never manage the workspace.
	if err := f.workspaceService.SetMembershipRole(ctx, f.owner, f.workspace, account.UserID, "administrator"); err == nil {
		t.Fatal("service account was made an administrator")
	}
	var credentials int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM registry_local_credentials WHERE user_id = ?`, account.UserID).Scan(&credentials); err != nil || credentials != 0 {
		t.Fatalf("service account has local credentials: %d %v", credentials, err)
	}
	for _, role := range []repositories.GrantRole{repositories.GrantReader, repositories.GrantPublisher} {
		if _, err := f.repositoryService.GrantRepositoryRole(ctx, f.owner, f.workspace, f.repository, account.UserID, role); err != nil {
			t.Fatal(err)
		}
	}
	image := f.name(f.repository, "ci/app")
	push := func(token string) int {
		content := []byte("ci build " + uuid.NewString())
		return f.do(http.MethodPost, image+"/blobs/uploads/?digest="+ociDigest(content), token, "application/octet-stream", content).Code
	}

	// Static tokens issued by a manager on the account's behalf.
	issued := call(http.MethodPost, "/api/v1/workspaces/"+f.workspace+"/service-accounts/"+account.UserID+"/tokens", fmt.Sprintf(`{"repository_id":%q,"kind":"oci-write","ttl_seconds":3600}`, f.repository))
	var static serviceTokenResponse
	if err := json.Unmarshal(issued.Body.Bytes(), &static); err != nil || issued.Code != http.StatusCreated || !strings.HasPrefix(static.Bearer, "prow_") {
		t.Fatalf("issue service account token: %d %s", issued.Code, issued.Body.String())
	}
	if code := push(static.Bearer); code != http.StatusCreated {
		t.Fatalf("push with a service account token: %d", code)
	}
	if listed := call(http.MethodGet, "/api/v1/workspaces/"+f.workspace+"/service-accounts/"+account.UserID+"/tokens", ""); !strings.Contains(listed.Body.String(), static.TokenID) || strings.Contains(listed.Body.String(), static.Bearer) {
		t.Fatalf("token list: %s", listed.Body.String())
	}
	if bad := call(http.MethodPost, "/api/v1/workspaces/"+f.workspace+"/service-accounts/"+account.UserID+"/tokens", fmt.Sprintf(`{"repository_id":%q,"kind":"root"}`, f.repository)); bad.Code != http.StatusBadRequest {
		t.Fatalf("unknown token kind: %d", bad.Code)
	}
	// A human user is not a service account.
	if response := call(http.MethodPost, "/api/v1/workspaces/"+f.workspace+"/service-accounts/"+f.owner+"/tokens", fmt.Sprintf(`{"repository_id":%q,"kind":"read"}`, f.repository)); response.Code != http.StatusNotFound {
		t.Fatalf("tokens for a human through the service account API: %d", response.Code)
	}
	if revoked := call(http.MethodDelete, "/api/v1/workspaces/"+f.workspace+"/service-accounts/"+account.UserID+"/tokens/oci-write/"+static.TokenID, ""); revoked.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", revoked.Code)
	}
	if code := push(static.Bearer); code != http.StatusUnauthorized {
		t.Fatalf("revoked token pushed: %d", code)
	}

	// Trusted publishing.
	publishers := "/api/v1/workspaces/" + f.workspace + "/repositories/" + f.repository + "/trusted-publishers"
	if bad := call(http.MethodPost, publishers, fmt.Sprintf(`{"service_account_id":%q,"repository":"octo/app","ref":"main"}`, account.UserID)); bad.Code != http.StatusBadRequest {
		t.Fatalf("ref without refs/ prefix: %d", bad.Code)
	}
	if bad := call(http.MethodPost, publishers, fmt.Sprintf(`{"service_account_id":%q,"repository":"octo/app","ref":"refs/heads/main"}`, f.owner)); bad.Code != http.StatusConflict {
		t.Fatalf("publisher bound to a human: %d", bad.Code)
	}
	if response := call(http.MethodPost, publishers, fmt.Sprintf(`{"service_account_id":%q,"repository":"Octo/App","ref":"refs/heads/main"}`, account.UserID)); response.Code != http.StatusCreated {
		t.Fatalf("create trusted publisher: %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, publishers, fmt.Sprintf(`{"service_account_id":%q,"repository":"octo/app","ref":"refs/tags/v*","environment":"release"}`, account.UserID)); response.Code != http.StatusCreated {
		t.Fatalf("create tag publisher: %d", response.Code)
	}
	exchange := func(token string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"token": token, "workspace_id": f.workspace, "repository_id": f.repository})
		request := httptest.NewRequest(http.MethodPost, "https://registry.example/api/v1/trusted-publishing/github/exchange", bytes.NewReader(body))
		request.Host = "registry.example"
		request.Header.Set("Content-Type", "application/json")
		request.RemoteAddr = "192.0.2.10:1234"
		request.TLS = &tls.ConnectionState{}
		response := httptest.NewRecorder()
		handler.ServeHTTP(testDeadlineResponse{ResponseRecorder: response}, request)
		return response
	}
	identity := github.token(t, nil)
	exchanged := exchange(identity)
	var tokens struct {
		Write serviceTokenResponse  `json:"write"`
		Read  *serviceTokenResponse `json:"read"`
	}
	if err := json.Unmarshal(exchanged.Body.Bytes(), &tokens); err != nil || exchanged.Code != http.StatusOK || tokens.Read == nil || tokens.Write.Kind != "oci-write" {
		t.Fatalf("exchange: %d %s", exchanged.Code, exchanged.Body.String())
	}
	expires, _ := time.Parse(time.RFC3339Nano, tokens.Write.ExpiresAt)
	if time.Until(expires) > 16*time.Minute {
		t.Fatalf("exchanged token lives too long: %s", tokens.Write.ExpiresAt)
	}
	if code := push(tokens.Write.Bearer); code != http.StatusCreated {
		t.Fatalf("push with an exchanged token: %d", code)
	}
	if response := exchange(identity); response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "token_already_used") {
		t.Fatalf("replayed identity token: %d %s", response.Code, response.Body.String())
	}
	for name, claims := range map[string]map[string]any{
		"other repository":     {"repository": "octo/other"},
		"other branch":         {"ref": "refs/heads/feature"},
		"pull request ref":     {"ref": "refs/pull/1/merge", "event_name": "pull_request"},
		"pull_request_target":  {"event_name": "pull_request_target"},
		"other audience":       {"aud": "https://elsewhere.example"},
		"expired":              {"exp": time.Now().Add(-time.Minute).Unix()},
		"no jti":               {"jti": nil},
		"recreated repository": {"repository_id": "9999"},
		"tag without env":      {"ref": "refs/tags/v1.0.0"},
		"tag other env":        {"ref": "refs/tags/v1.0.0", "environment": "staging"},
		"bare tag prefix":      {"ref": "refs/tags/v", "environment": "release"},
	} {
		if response := exchange(github.token(t, claims)); response.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d %s", name, response.Code, response.Body.String())
		}
	}
	if response := exchange(github.token(t, map[string]any{"ref": "refs/tags/v1.0.0", "environment": "release"})); response.Code != http.StatusOK {
		t.Fatalf("tag release exchange: %d %s", response.Code, response.Body.String())
	}
	forged := github.token(t, nil)
	if response := exchange(forged[:len(forged)-4] + "AAAA"); response.Code != http.StatusUnauthorized {
		t.Fatalf("forged signature: %d", response.Code)
	}
	listed := call(http.MethodGet, publishers, "")
	if !strings.Contains(listed.Body.String(), `"repository_id":"4242"`) || !strings.Contains(listed.Body.String(), `"repository":"octo/app"`) {
		t.Fatalf("publisher list does not show the pinned repository: %s", listed.Body.String())
	}

	// Disabling the account revokes its tokens and stops trusted publishing.
	if response := call(http.MethodDelete, "/api/v1/workspaces/"+f.workspace+"/service-accounts/"+account.UserID, ""); response.Code != http.StatusNoContent {
		t.Fatalf("disable: %d", response.Code)
	}
	if code := push(tokens.Write.Bearer); code != http.StatusUnauthorized {
		t.Fatalf("token of a disabled account pushed: %d", code)
	}
	if response := exchange(github.token(t, nil)); response.Code != http.StatusUnauthorized {
		t.Fatalf("exchange for a disabled account: %d", response.Code)
	}
}
