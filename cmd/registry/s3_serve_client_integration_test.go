//go:build integration && linux

package main

import (
	"context"
	"encoding/pem"
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
	"private-registry/internal/spikes/remotebackup"
	"private-registry/internal/spikes/testinfra"
)

// TestServeS3StorageRealClientJourney proves that the serve command, selected
// purely through configuration, keeps package bytes in the S3-compatible
// bucket instead of the local object store. Floci is a development fixture:
// this does not qualify R2, B2 or any other real backend.
func TestServeS3StorageRealClientJourney(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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
	// The registry only speaks HTTPS to object storage; the fixture gets a
	// local TLS front whose certificate is trusted through REGISTRY_S3_CA_FILE.
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
	t.Setenv("REGISTRY_STORAGE_DRIVER", "s3")
	t.Setenv("REGISTRY_S3_ENDPOINT", tlsFront.URL)
	t.Setenv("REGISTRY_S3_REGION", "us-east-1")
	t.Setenv("REGISTRY_S3_BUCKET", bucket)
	t.Setenv("REGISTRY_S3_PREFIX", "registry/objects")
	t.Setenv("REGISTRY_S3_ACCESS_KEY_ID_FILE", accessKeyFile)
	t.Setenv("REGISTRY_S3_SECRET_ACCESS_KEY_FILE", secretKeyFile)
	t.Setenv("REGISTRY_S3_CA_FILE", caFile)
	t.Setenv("REGISTRY_S3_ALLOWED_NETWORKS", host+"/32")

	exerciseNPMServeJourney(t, root)

	listed, err := admin.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String("registry/objects/workspaces/")})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Contents) == 0 {
		t.Fatal("published package bytes are not in the S3 bucket")
	}
	if _, err := os.Stat(filepath.Join(root, "data", "object-store")); !os.IsNotExist(err) {
		t.Fatalf("local object store was used with the S3 driver: %v", err)
	}
	staged, err := os.ReadDir(filepath.Join(root, "data", "s3-staging"))
	if err != nil || len(staged) != 0 {
		t.Fatalf("S3 staging was not left empty: entries=%d err=%v", len(staged), err)
	}
}
