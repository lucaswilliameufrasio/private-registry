package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

type failingS3Body struct{ io.Reader }

func (f *failingS3Body) Close() error {
	return errors.New("synthetic close failure")
}

type s3RoundTripper func(*http.Request) (*http.Response, error)

func (f s3RoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestS3RejectsRemoteBodyCloseFailure(t *testing.T) {
	payload := []byte("synthetic object")
	hash := sha256.Sum256(payload)
	client := s3.NewFromConfig(aws.Config{
		Region:      "synthetic-region",
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient: &http.Client{Transport: s3RoundTripper(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Length": []string{strconv.Itoa(len(payload))}}, ContentLength: int64(len(payload)), Body: &failingS3Body{Reader: bytes.NewReader(payload)}, Request: request}, nil
		})},
		Retryer: func() aws.Retryer { return aws.NopRetryer{} },
	}, func(options *s3.Options) {
		options.BaseEndpoint = aws.String("https://fixture.invalid")
		options.UsePathStyle = true
	})
	staging := filepath.Join(t.TempDir(), "staging")
	driver, err := NewS3(client, "synthetic-bucket", "", staging, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := ObjectKey{WorkspaceID: uuid.NewString(), SHA256: hex.EncodeToString(hash[:])}
	reader, _, err := driver.Open(ctx, key)
	if !errors.Is(err, ErrObjectIntegrity) || reader != nil {
		t.Fatalf("failed remote close exposed object: reader=%v err=%v", reader, err)
	}
	entries, err := os.ReadDir(staging)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed remote close left staging: entries=%d err=%v", len(entries), err)
	}
}

func TestS3AmbiguousPutRequiresConditionalWriteAndVerifiedReadback(t *testing.T) {
	var lock sync.Mutex
	var stored []byte
	var conditional string
	var corruptReadback bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		switch request.Method {
		case http.MethodPut:
			conditional = request.Header.Get("If-None-Match")
			stored, _ = io.ReadAll(request.Body)
			// The server commits bytes but the caller receives an uncertain result.
			http.Error(response, "synthetic write response lost", http.StatusInternalServerError)
		case http.MethodGet:
			if corruptReadback {
				_, _ = response.Write([]byte("synthetic corruption"))
			} else {
				_, _ = response.Write(stored)
			}
		default:
			http.Error(response, "unsupported", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)
	client := s3.NewFromConfig(aws.Config{
		Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		Retryer: func() aws.Retryer { return aws.NopRetryer{} },
	}, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(server.URL)
		options.UsePathStyle = true
	})
	staging := filepath.Join(t.TempDir(), "staging")
	driver, err := NewS3(client, "synthetic-bucket", "", staging, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Put(context.Background(), uuid.NewString(), bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("operation without a deadline was accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	payload := []byte("synthetic ambiguous write")
	info, err := driver.Put(ctx, uuid.NewString(), bytes.NewReader(payload), int64(len(payload)))
	if err != nil || info.Size != int64(len(payload)) {
		t.Fatalf("verified ambiguous write = %+v, %v", info, err)
	}
	lock.Lock()
	if conditional != "*" || !bytes.Equal(stored, payload) {
		lock.Unlock()
		t.Fatalf("conditional write header=%q or recorded content differs", conditional)
	}
	lock.Unlock()
	bounded, err := NewBoundedDriver(driver, 1)
	if err != nil {
		t.Fatal(err)
	}
	reader, _, err := bounded.Open(ctx, info.Key)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(staging)
	if err != nil || len(entries) != 1 {
		t.Fatalf("verified open staging: %d entries, error=%v", len(entries), err)
	}
	if _, _, err := bounded.Open(ctx, info.Key); !errors.Is(err, ErrCapacity) {
		t.Fatalf("open did not retain staging capacity: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	lock.Lock()
	corruptReadback = true
	lock.Unlock()
	if _, err := driver.Put(ctx, uuid.NewString(), bytes.NewReader(payload), int64(len(payload))); err == nil {
		t.Fatal("ambiguous write with corrupt readback was accepted")
	}
	entries, err = os.ReadDir(staging)
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging cleanup: %d entries, error=%v", len(entries), err)
	}
}
