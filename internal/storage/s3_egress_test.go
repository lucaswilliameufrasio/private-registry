package storage

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"private-registry/internal/egress"
)

func TestExperimentalS3ClientHonorsInjectedHTTPSPolicy(t *testing.T) {
	var mu sync.Mutex
	var content []byte
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		switch request.Method {
		case http.MethodPut:
			content, _ = io.ReadAll(request.Body)
			response.WriteHeader(http.StatusOK)
		case http.MethodGet:
			_, _ = response.Write(content)
		default:
			http.Error(response, "unsupported", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	makeDriver := func(destinations []egress.Destination) *S3 {
		t.Helper()
		client, err := egress.NewHTTPSClient(destinations, roots)
		if err != nil {
			t.Fatal(err)
		}
		s3client := s3.NewFromConfig(aws.Config{
			Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""),
			Retryer: func() aws.Retryer { return aws.NopRetryer{} }, HTTPClient: client,
		}, func(options *s3.Options) {
			options.BaseEndpoint = aws.String(server.URL)
			options.UsePathStyle = true
		})
		driver, err := NewS3(s3client, "synthetic-bucket", "", filepath.Join(t.TempDir(), "staging"), 1024)
		if err != nil {
			t.Fatal(err)
		}
		return driver
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	data := []byte("synthetic object")
	workspace := uuid.NewString()
	if _, err := makeDriver(nil).Put(ctx, workspace, bytes.NewReader(data), int64(len(data))); err == nil {
		t.Fatal("S3 write succeeded with no outbound destination")
	}
	mu.Lock()
	before := requests
	mu.Unlock()
	if before != 0 {
		t.Fatal("denied S3 request reached the fixture")
	}
	allowed := []egress.Destination{{Origin: server.URL, CIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}
	driver := makeDriver(allowed)
	info, err := driver.Put(ctx, workspace, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal("allowlisted S3 fixture write:", err)
	}
	reader, _, err := driver.Open(ctx, info.Key)
	if err != nil {
		t.Fatal("allowlisted S3 fixture read:", err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, data) {
		t.Fatal("allowlisted S3 fixture returned different data")
	}
}
