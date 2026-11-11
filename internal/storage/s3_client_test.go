package storage

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

func TestRestrictedS3ClientEnforcesOriginNetworkAndTLS(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets/></ListAllMyBucketsResult>`))
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	settings := S3ClientSettings{
		Origin: server.URL, Region: "synthetic-region", Networks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		RootCAs: roots, Credentials: credentials.NewStaticCredentialsProvider("synthetic-access", "synthetic-secret", ""),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := NewRestrictedS3Client(settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListBuckets(ctx, &s3.ListBucketsInput{}); err != nil {
		t.Fatalf("allowed S3 request failed: %v", err)
	}
	before := requests.Load()
	settings.Networks = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	denied, err := NewRestrictedS3Client(settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.ListBuckets(ctx, &s3.ListBucketsInput{}); err == nil || requests.Load() != before {
		t.Fatalf("denied network reached S3 endpoint: %v", err)
	}
	settings.Networks = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	settings.RootCAs = x509.NewCertPool()
	untrusted, err := NewRestrictedS3Client(settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted.ListBuckets(ctx, &s3.ListBucketsInput{}); err == nil || requests.Load() != before {
		t.Fatalf("untrusted TLS reached S3 handler: %v", err)
	}
	settings.Origin = "http://127.0.0.1:1234"
	if _, err := NewRestrictedS3Client(settings); err == nil {
		t.Fatal("plaintext S3 origin was accepted")
	}
	settings.Origin = server.URL
	settings.Credentials = nil
	if _, err := NewRestrictedS3Client(settings); err == nil {
		t.Fatal("implicit credentials were accepted")
	}
}

func TestRestrictedS3ClientDoesNotFollowRedirects(t *testing.T) {
	var forwarded atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	roots.AddCert(target.Certificate())
	client, err := NewRestrictedS3Client(S3ClientSettings{
		Origin: origin.URL, Region: "synthetic-region", Networks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		RootCAs: roots, Credentials: credentials.NewStaticCredentialsProvider("synthetic-access", "synthetic-secret", ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.ListBuckets(ctx, &s3.ListBucketsInput{}); err == nil || forwarded.Load() != 0 {
		t.Fatalf("redirect reached a different origin: count=%d err=%v", forwarded.Load(), err)
	}
}

func TestRestrictedS3StorageComposesVerifiedReadAndAdmission(t *testing.T) {
	var mu sync.Mutex
	var stored []byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("If-None-Match") != "*" {
				http.Error(w, "conditional write required", http.StatusBadRequest)
				return
			}
			stored, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			_, _ = w.Write(stored)
		default:
			http.Error(w, "unsupported", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	staging := filepath.Join(t.TempDir(), "staging")
	settings := S3ClientSettings{
		Origin: server.URL, Region: "synthetic-region", Networks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		RootCAs: roots, Credentials: credentials.NewStaticCredentialsProvider("synthetic-access", "synthetic-secret", ""),
	}
	driver, err := NewRestrictedS3Storage(settings, "synthetic-bucket", "fixture", staging, 1024, 1, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	payload := []byte("synthetic bounded s3 object")
	info, err := driver.Put(context.Background(), uuid.NewString(), bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	reader, gotInfo, err := driver.Open(ctx, info.Key)
	if err != nil || gotInfo != info {
		t.Fatalf("verified open failed: %v", err)
	}
	if _, _, err := driver.Open(ctx, info.Key); !errors.Is(err, ErrCapacity) {
		_ = reader.Close()
		t.Fatalf("reader did not retain capacity: %v", err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, payload) {
		t.Fatalf("verified content differs: read=%v close=%v", readErr, closeErr)
	}
	entries, err := os.ReadDir(staging)
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging remains after close: entries=%d err=%v", len(entries), err)
	}
}

func TestS3ActiveStagingCeiling(t *testing.T) {
	if got, err := S3ActiveStagingCeiling(1024, 3); err != nil || got != 6147 {
		t.Fatalf("incorrect active staging ceiling: %d, %v", got, err)
	}
	if got, err := S3ActiveStagingCeiling(1<<30, 128); err != nil || got != (256<<30)+128 {
		t.Fatalf("incorrect maximum staging ceiling: %d, %v", got, err)
	}
	for _, item := range []struct {
		size  int64
		count int
	}{{0, 1}, {1<<30 + 1, 1}, {1, 0}, {1, 129}} {
		if _, err := S3ActiveStagingCeiling(item.size, item.count); err == nil {
			t.Fatal("invalid staging limits accepted")
		}
	}
}
