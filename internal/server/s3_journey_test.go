//go:build linux

package server

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/google/uuid"
	"private-registry/internal/artifacts"
	"private-registry/internal/config"
	"private-registry/internal/storage"
)

func TestS3SyntheticHTTPSGenericHTTPJourney(t *testing.T) {
	var mu sync.Mutex
	var requests atomic.Int64
	objects := make(map[string][]byte)
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("If-None-Match") != "*" {
				http.Error(w, "conditional write required", http.StatusBadRequest)
				return
			}
			if _, exists := objects[r.URL.Path]; exists {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
			if err != nil || len(body) > 1<<20 {
				http.Error(w, "invalid fixture body", http.StatusBadRequest)
				return
			}
			objects[r.URL.Path] = body
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			body, exists := objects[r.URL.Path]
			if !exists {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(body)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer endpoint.Close()
	roots := x509.NewCertPool()
	roots.AddCert(endpoint.Certificate())
	driver, err := storage.NewRestrictedS3Storage(storage.S3ClientSettings{
		Origin: endpoint.URL, Region: "synthetic-region", Networks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		RootCAs: roots, Credentials: credentials.NewStaticCredentialsProvider("synthetic-access", "synthetic-secret", ""),
	}, "synthetic-bucket", "test", filepath.Join(t.TempDir(), "stage"), 1<<20, 2, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newAuthHTTPFixture(t)
	fixture.artifactService, err = artifacts.New(fixture.db, config.SQLite, fixture.repositoryService, driver, artifacts.Options{MaxUploadBytes: 1 << 20, MaxConcurrentUploads: 2})
	if err != nil {
		t.Fatal(err)
	}
	exerciseAuthHTTPGenericArtifactPublication(t, fixture)
	handler, err := NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/v1/token/workspaces/%s/repositories/%s/files/%s", uuid.NewString(), uuid.NewString(), uuid.NewString())
	before := requests.Load()
	denied := authBearerHTTPRequest(handler, http.MethodGet, path, "assets.example", "Bearer invalid", "", "")
	if denied.Code != http.StatusUnauthorized || requests.Load() != before {
		t.Fatalf("unauthorized request reached object storage: status=%d", denied.Code)
	}
}
