//go:build integration && linux

package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	"private-registry/internal/objectmaint"
	"private-registry/internal/repositories"
	"private-registry/internal/spikes/remotebackup"
	"private-registry/internal/spikes/testinfra"
)

// TestMigrateObjectsFromFilesystemToS3 moves an installation that started
// with local storage to S3: packages published before the move are served
// from the bucket afterwards with their original integrity.
func TestMigrateObjectsFromFilesystemToS3(t *testing.T) {
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

	// Life with local storage.
	root := t.TempDir()
	exerciseNPMServeJourney(t, root)

	secretsDir := filepath.Join(root, "s3-secrets")
	if err := os.Mkdir(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		filepath.Join(secretsDir, "access-key-id"):     []byte("test\n"),
		filepath.Join(secretsDir, "secret-access-key"): []byte("test\n"),
		filepath.Join(secretsDir, "ca.pem"):            pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsFront.Certificate().Raw}),
	}
	for path, contents := range files {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("REGISTRY_STORAGE_DRIVER", "s3")
	t.Setenv("REGISTRY_S3_ENDPOINT", tlsFront.URL)
	t.Setenv("REGISTRY_S3_REGION", "us-east-1")
	t.Setenv("REGISTRY_S3_BUCKET", bucket)
	t.Setenv("REGISTRY_S3_PREFIX", "registry/objects")
	t.Setenv("REGISTRY_S3_ACCESS_KEY_ID_FILE", filepath.Join(secretsDir, "access-key-id"))
	t.Setenv("REGISTRY_S3_SECRET_ACCESS_KEY_FILE", filepath.Join(secretsDir, "secret-access-key"))
	t.Setenv("REGISTRY_S3_CA_FILE", filepath.Join(secretsDir, "ca.pem"))
	t.Setenv("REGISTRY_S3_ALLOWED_NETWORKS", host+"/32")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(ctx, []string{"migrate-objects"}, logger); err != nil {
		t.Fatalf("migrate-objects: %v", err)
	}
	if err := run(ctx, []string{"migrate-objects"}, logger); err != nil {
		t.Fatalf("repeated migrate-objects: %v", err)
	}
	listed, err := admin.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String("registry/objects/workspaces/")})
	if err != nil || len(listed.Contents) == 0 {
		t.Fatalf("migrated objects: %v", err)
	}
	// The local copy is kept; the operator removes it when satisfied.
	if _, err := os.Stat(filepath.Join(root, "data", "object-store", "objects")); err != nil {
		t.Fatalf("filesystem objects were removed: %v", err)
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
	// Prove the bytes come from the bucket: remove the local copy first.
	if err := os.RemoveAll(filepath.Join(root, "data", "object-store")); err != nil {
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
	// Offline maintenance refuses to run while serve holds the data directory.
	if err := run(ctx, []string{"collect-objects"}, logger); !errors.Is(err, objectmaint.ErrInstanceRunning) {
		t.Fatalf("collect-objects while serving: %v", err)
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
		t.Fatalf("migrated tarball integrity = %s, published %s", got, version.Dist.Integrity)
	}
}
