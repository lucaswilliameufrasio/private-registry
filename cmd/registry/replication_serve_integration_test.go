//go:build integration && linux && amd64

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
	"private-registry/internal/repositories"
	"private-registry/internal/spikes/remotebackup"
	"private-registry/internal/spikes/testinfra"
)

// TestServeDisasterRecoveryDrill loses the whole data directory of a running
// installation and rebuilds it: the database comes back from SQLite
// replication, the package bytes from the object bucket, and the master key
// from the operator's own copy. The published package must then be served
// again with its original integrity. Floci stands in for the bucket; this does
// not qualify any real provider.
func TestServeDisasterRecoveryDrill(t *testing.T) {
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
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, floci.Endpoint+"/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
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

	root := t.TempDir()
	secretsDir := filepath.Join(root, "s3-secrets")
	if err := os.Mkdir(secretsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	accessKeyFile := filepath.Join(secretsDir, "access-key-id")
	secretKeyFile := filepath.Join(secretsDir, "secret-access-key")
	caFile := filepath.Join(secretsDir, "ca.pem")
	for path, contents := range map[string][]byte{
		accessKeyFile: []byte("test\n"),
		secretKeyFile: []byte("test\n"),
		caFile:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsFront.Certificate().Raw}),
	} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Package objects and the database replica share the fixture bucket under
	// separate prefixes; in production they may be different buckets.
	for _, prefix := range []string{"REGISTRY_S3_", "REGISTRY_REPLICATION_S3_"} {
		t.Setenv(prefix+"ENDPOINT", tlsFront.URL)
		t.Setenv(prefix+"REGION", "us-east-1")
		t.Setenv(prefix+"BUCKET", bucket)
		t.Setenv(prefix+"ACCESS_KEY_ID_FILE", accessKeyFile)
		t.Setenv(prefix+"SECRET_ACCESS_KEY_FILE", secretKeyFile)
		t.Setenv(prefix+"CA_FILE", caFile)
		t.Setenv(prefix+"ALLOWED_NETWORKS", host+"/32")
	}
	t.Setenv("REGISTRY_STORAGE_DRIVER", "s3")
	t.Setenv("REGISTRY_S3_PREFIX", "registry/objects")
	t.Setenv("REGISTRY_REPLICATION_ENABLED", "true")
	t.Setenv("REGISTRY_REPLICATION_S3_PREFIX", "registry/dr")
	// Long enough that only the first cycle and the shutdown flush run: the
	// publication below must reach the bucket through the final flush.
	t.Setenv("REGISTRY_REPLICATION_INTERVAL_SECONDS", "3600")

	// A normal life: publish and install with the real npm client, then stop.
	exerciseNPMServeJourney(t, root)

	dataDir := filepath.Join(root, "data")
	if entries, err := os.ReadDir(filepath.Join(dataDir, "replication")); err != nil || len(entries) != 1 {
		t.Fatalf("local replication spool: %d entries, %v", len(entries), err)
	}
	replicated, err := admin.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String("registry/dr/generations/")})
	if err != nil || len(replicated.Contents) < 2 {
		t.Fatalf("replicated objects: %d, %v", len(replicated.Contents), err)
	}

	// Disaster: the data directory is gone. The master key lives outside it.
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(ctx, []string{"serve"}, logger); err == nil {
		t.Fatal("serve started without a database")
	}
	// The failed start created an empty database file; restore refuses to
	// overwrite anything, so the operator clears the directory first.
	if err := run(ctx, []string{"restore-database"}, logger); err == nil {
		t.Fatal("restore-database overwrote an existing database file")
	}
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"restore-database"}, logger); err != nil {
		t.Fatalf("restore-database: %v", err)
	}
	if err := run(ctx, []string{"restore-database"}, logger); err == nil {
		t.Fatal("second restore-database overwrote the restored database")
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
		t.Fatalf("published package is missing from the restored database: %v", err)
	}
	repos, err := repositories.New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	readToken, err := repos.IssuePersonalReadToken(ctx, owner, workspace, repository, time.Hour)
	if err != nil {
		t.Fatalf("grants did not survive the restore: %v", err)
	}

	serverCtx, stop := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { result <- run(serverCtx, []string{"serve"}, logger) }()
	defer func() {
		stop()
		if err := <-result; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("stop restored server: %v", err)
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
			t.Fatal("restored server did not become ready")
		case err := <-result:
			t.Fatalf("restored server stopped during startup: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
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
			t.Fatalf("GET %s from the restored server: status=%d err=%v", path, response.StatusCode, err)
		}
		return body
	}
	base := "/npm/" + workspace + "/" + repository + "/"
	var packument struct {
		Versions map[string]struct {
			Dist struct {
				Tarball   string `json:"tarball"`
				Integrity string `json:"integrity"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(get(base+"@fixture%2fserve-package"), &packument); err != nil {
		t.Fatal(err)
	}
	version, ok := packument.Versions["1.0.0"]
	if !ok || !strings.HasPrefix(version.Dist.Integrity, "sha512-") {
		t.Fatalf("restored packument lacks the published version: %+v", packument)
	}
	tarballURL, err := url.Parse(version.Dist.Tarball)
	if err != nil {
		t.Fatal(err)
	}
	// The bytes come from the object bucket, which the disaster did not touch.
	tarball := get(tarballURL.EscapedPath())
	sum := sha512.Sum512(tarball)
	if got := "sha512-" + base64.StdEncoding.EncodeToString(sum[:]); got != version.Dist.Integrity {
		t.Fatalf("restored tarball integrity = %s, published %s", got, version.Dist.Integrity)
	}
}
