package trustedpub_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/bootstrap"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/repositories"
	"private-registry/internal/trustedpub"
	"private-registry/internal/workspaces"
)

const audience = "https://registry.example"

func TestSQLiteTrustedPublishing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: dataDir, DatabaseDriver: config.SQLite, DatabaseDSN: filepath.Join(dataDir, "registry.sqlite"), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	ExerciseTrustedPublishing(t, ctx, db, config.SQLite)
}

// ExerciseTrustedPublishing is shared with the PostgreSQL test.
func ExerciseTrustedPublishing(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "ci", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	sign := func(repository, repositoryID, ref string) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"ci","typ":"JWT"}`))
		claims, _ := json.Marshal(map[string]any{"iss": issuer, "aud": audience, "sub": "repo:" + repository, "repository": repository, "repository_id": repositoryID, "ref": ref, "event_name": "push", "jti": uuid.NewString(), "exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix()})
		body := header + "." + base64.RawURLEncoding.EncodeToString(claims)
		digest := sha256.Sum256([]byte(body))
		signature, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		return body + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	owner, err := bootstrap.CreateFirstAdmin(ctx, db, driver, bootstrap.AdminInput{LoginName: "ci.owner", DisplayName: "CI", Email: "ci@example.invalid", Password: []byte("synthetic-ci-password-never-reuse"), OperatorLabel: "synthetic-test-operator"})
	if err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "ci", "CI")
	if err != nil {
		t.Fatal(err)
	}
	account, err := workspaceService.CreateServiceAccount(ctx, owner, workspace.ID, "release")
	if err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, owner, workspace.ID, account.UserID, workspaces.RoleAdministrator); !errors.Is(err, workspaces.ErrServiceAccountRole) {
		t.Fatalf("service account elevated: %v", err)
	}
	repos, err := repositories.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	if err := repos.EnableFormatCreation(repositories.FormatNPM); err != nil {
		t.Fatal(err)
	}
	repository, err := repos.CreateWithFormat(ctx, owner, workspace.ID, "packages", "Packages", repositories.FormatNPM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace.ID, repository.ID, account.UserID, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Timeout = 5 * time.Second
	service, err := trustedpub.New(db, driver, repos, issuer, audience, client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreatePublisher(ctx, owner, workspace.ID, repository.ID, account.UserID, "octo/lib", "refs/heads/main", ""); err != nil {
		t.Fatal(err)
	}
	exchanged, err := service.Exchange(ctx, sign("octo/lib", "77", "refs/heads/main"), workspace.ID, repository.ID)
	if err != nil || exchanged.Write.Kind != repositories.TokenNPMWrite || exchanged.Write.Bearer == "" {
		t.Fatalf("exchange: %+v %v", exchanged, err)
	}
	// Without a reader grant, no read token is issued.
	if exchanged.Read.Bearer != "" {
		t.Fatal("read token issued without a reader grant")
	}
	if err := repos.WithNPMWriteTokenTransaction(ctx, exchanged.Write.Bearer, workspace.ID, repository.ID, func(_ *sql.Tx, user string) error {
		if user != account.UserID {
			t.Fatalf("token owner %s, want the service account", user)
		}
		return nil
	}); err != nil {
		t.Fatalf("exchanged token does not authorize: %v", err)
	}
	if _, err := service.Exchange(ctx, sign("octo/lib", "78", "refs/heads/main"), workspace.ID, repository.ID); !errors.Is(err, trustedpub.ErrNoPublisher) {
		t.Fatalf("repository ID was not pinned: %v", err)
	}
	// Two concurrent exchanges of one identity token: exactly one succeeds.
	token := sign("octo/lib", "77", "refs/heads/main")
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := service.Exchange(ctx, token, workspace.ID, repository.ID)
			results <- err
		}()
	}
	succeeded := 0
	for range 2 {
		if err := <-results; err == nil {
			succeeded++
		} else if !errors.Is(err, trustedpub.ErrReplay) {
			t.Fatalf("concurrent exchange: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("identity token exchanged %d times", succeeded)
	}
	// Losing the publisher grant stops exchanges.
	if err := repos.RevokeRepositoryRole(ctx, owner, workspace.ID, repository.ID, account.UserID, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Exchange(ctx, sign("octo/lib", "77", "refs/heads/main"), workspace.ID, repository.ID); !errors.Is(err, trustedpub.ErrNoPublisher) {
		t.Fatalf("exchange without a publisher grant: %v", err)
	}
}
