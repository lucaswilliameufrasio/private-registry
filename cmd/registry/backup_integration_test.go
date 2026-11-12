//go:build integration && linux

package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	"errors"
	"filippo.io/age"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/repositories"
	"private-registry/internal/spikes/remotebackup"
	"private-registry/internal/spikes/testinfra"
)

// TestBackupAndRestoreThroughCommands loses the whole data directory of an
// installation with local storage and rebuilds it from the backup bucket
// alone: database and package bytes come back and the published package is
// served with its original integrity.
func TestBackupAndRestoreThroughCommands(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	floci, err := testinfra.StartFloci(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := floci.Stop(); err != nil {
			t.Error(err)
		}
	})
	for {
		response, err := (&http.Client{Timeout: time.Second}).Get(floci.Endpoint + "/health")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("isolated Floci did not become ready")
		case <-time.After(50 * time.Millisecond):
		}
	}
	admin, err := remotebackup.NewClient(floci.Endpoint, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	bucket := "synthetic-" + uuid.NewString()
	if _, err := admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	upstream, err := url.Parse(floci.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	tlsFront := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(upstream))
	defer tlsFront.Close()
	host, _, err := net.SplitHostPort(strings.TrimPrefix(tlsFront.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}

	// Life with local storage; the backup bucket is the only copy that
	// survives the disaster.
	root := t.TempDir()
	exerciseNPMServeJourney(t, root)

	secretsDir := filepath.Join(root, "backup-secrets")
	if err := os.Mkdir(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(secretsDir, "identity.txt")
	files := map[string][]byte{
		filepath.Join(secretsDir, "access-key-id"):     []byte("test\n"),
		filepath.Join(secretsDir, "secret-access-key"): []byte("test\n"),
		filepath.Join(secretsDir, "ca.pem"):            pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsFront.Certificate().Raw}),
		identityPath:                                   []byte("# synthetic test identity\n" + identity.String() + "\n"),
	}
	for path, contents := range files {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("REGISTRY_BACKUP_S3_ENDPOINT", tlsFront.URL)
	t.Setenv("REGISTRY_BACKUP_S3_REGION", "us-east-1")
	t.Setenv("REGISTRY_BACKUP_S3_BUCKET", bucket)
	t.Setenv("REGISTRY_BACKUP_S3_PREFIX", "registry/backups")
	t.Setenv("REGISTRY_BACKUP_S3_ACCESS_KEY_ID_FILE", filepath.Join(secretsDir, "access-key-id"))
	t.Setenv("REGISTRY_BACKUP_S3_SECRET_ACCESS_KEY_FILE", filepath.Join(secretsDir, "secret-access-key"))
	t.Setenv("REGISTRY_BACKUP_S3_CA_FILE", filepath.Join(secretsDir, "ca.pem"))
	t.Setenv("REGISTRY_BACKUP_S3_ALLOWED_NETWORKS", host+"/32")
	t.Setenv("REGISTRY_BACKUP_AGE_RECIPIENT", identity.Recipient().String())

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(ctx, []string{"backup", "--identity", identityPath}, logger); err == nil {
		t.Fatal("backup accepted an identity it must never need")
	}
	if err := run(ctx, []string{"backup"}, logger); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if err := run(ctx, []string{"verify-backup", "--identity", identityPath}, logger); err != nil {
		t.Fatalf("verify-backup: %v", err)
	}
	if err := os.Chmod(identityPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"verify-backup", "--identity", identityPath}, logger); err == nil {
		t.Fatal("a world-readable identity file was accepted")
	}
	if err := os.Chmod(identityPath, 0o600); err != nil {
		t.Fatal(err)
	}

	// Disaster: the data directory, database and objects are gone.
	if err := os.RemoveAll(filepath.Join(root, "data")); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"restore-backup", "--identity", identityPath}, logger); err != nil {
		t.Fatalf("restore-backup: %v", err)
	}
	if err := run(ctx, []string{"restore-backup", "--identity", identityPath}, logger); err == nil {
		t.Fatal("restore-backup overwrote the restored database")
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
	t.Setenv("REGISTRY_CANONICAL_ORIGIN", "https://registry.example")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var owner, workspace, repository string
	if err := db.QueryRowContext(ctx, `SELECT packages.repository_id, repositories.workspace_id, repositories.created_by FROM registry_npm_packages AS packages JOIN registry_repositories AS repositories ON repositories.repository_id = packages.repository_id WHERE packages.name = '@fixture/serve-package'`).Scan(&repository, &workspace, &owner); err != nil {
		t.Fatal(err)
	}
	repos, err := repositories.New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	readToken, err := repos.IssuePersonalReadToken(ctx, owner, workspace, repository, time.Hour)
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
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
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
			t.Fatalf("server stopped: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	// Restoring onto a running installation is refused.
	if err := run(ctx, []string{"restore-backup", "--identity", identityPath}, logger); err == nil {
		t.Fatal("restore-backup ran against a live installation")
	}
	get := func(path string) []byte {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "registry.example"
		request.Header.Set("X-Forwarded-Proto", "https")
		request.Header.Set("Authorization", "Bearer "+readToken.Bearer)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %v", path, response.StatusCode, err)
		}
		return body
	}
	var packument struct {
		Versions map[string]struct {
			Dist struct {
				Tarball   string `json:"tarball"`
				Integrity string `json:"integrity"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(get("/npm/"+workspace+"/"+repository+"/@fixture%2fserve-package"), &packument); err != nil {
		t.Fatal(err)
	}
	version := packument.Versions["1.0.0"]
	tarballURL, err := url.Parse(version.Dist.Tarball)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum512(get(tarballURL.EscapedPath()))
	if got := "sha512-" + base64.StdEncoding.EncodeToString(sum[:]); got != version.Dist.Integrity {
		t.Fatalf("restored tarball integrity = %s, published %s", got, version.Dist.Integrity)
	}
}
