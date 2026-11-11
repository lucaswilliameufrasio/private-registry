//go:build integration

package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"private-registry/internal/spikes/remotebackup"
	"private-registry/internal/spikes/testinfra"
)

func TestS3DriverAgainstIsolatedFloci(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	fixture, err := testinfra.StartFloci(ctx)
	if err != nil {
		t.Fatal("start owned Floci:", err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Error("stop owned Floci:", err)
		}
	})
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, fixture.Endpoint+"/health", nil)
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
			t.Fatal("Floci did not become ready")
		case <-time.After(50 * time.Millisecond):
		}
	}
	client, err := remotebackup.NewClient(fixture.Endpoint, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	bucket := "synthetic-" + uuid.NewString()
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal("create owned fixture bucket:", err)
	}
	staging := filepath.Join(t.TempDir(), "staging")
	driver, err := NewS3(client, bucket, "synthetic", staging, 1024)
	if err != nil {
		t.Fatal(err)
	}
	workspace := uuid.NewString()
	payload := []byte("synthetic verified content")
	info, err := driver.Put(ctx, workspace, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal("put verified object:", err)
	}
	bounded, err := NewBoundedDriver(driver, 1)
	if err != nil {
		t.Fatal(err)
	}
	held, _, err := bounded.Open(ctx, info.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := bounded.OpenRange(ctx, info.Key, 0, 1); !errors.Is(err, ErrCapacity) {
		_ = held.Close()
		t.Fatalf("held S3 reader did not bound range staging: %v", err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	verifiedRange, _, err := bounded.OpenRange(ctx, info.Key, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifiedRange.Close(); err != nil {
		t.Fatal(err)
	}
	duplicate, err := driver.Put(ctx, workspace, bytes.NewReader(payload), int64(len(payload)))
	if err != nil || duplicate != info {
		t.Fatalf("deduplicate object = %+v, %v", duplicate, err)
	}
	other, err := driver.Put(ctx, uuid.NewString(), bytes.NewReader(payload), int64(len(payload)))
	if err != nil || other.Key.WorkspaceID == info.Key.WorkspaceID || other.Key.SHA256 != info.Key.SHA256 {
		t.Fatalf("workspace-isolated object = %+v, %v", other, err)
	}
	opened, openedInfo, err := driver.Open(ctx, info.Key)
	if err != nil {
		t.Fatal("open verified object:", err)
	}
	data, readErr := io.ReadAll(opened)
	closeErr := opened.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(data, payload) || openedInfo != info {
		t.Fatalf("verified object mismatch: read=%v close=%v info=%+v", readErr, closeErr, openedInfo)
	}
	ranged, _, err := driver.OpenRange(ctx, info.Key, 3, 5)
	if err != nil {
		t.Fatal("open verified range:", err)
	}
	rangeData, readErr := io.ReadAll(ranged)
	closeErr = ranged.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(rangeData, payload[3:8]) {
		t.Fatalf("verified range mismatch: read=%v close=%v", readErr, closeErr)
	}
	if _, err := driver.Put(ctx, workspace, bytes.NewReader(payload), 2); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("oversized object error = %v", err)
	}
	name, _, err := driver.objectName(info.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(name), Body: bytes.NewReader([]byte("synthetic tampering"))}); err != nil {
		t.Fatal("inject corruption in isolated fixture:", err)
	}
	if reader, _, err := driver.Open(ctx, info.Key); !errors.Is(err, ErrObjectIntegrity) || reader != nil {
		t.Fatalf("corrupted object exposed a reader: reader=%v err=%v", reader, err)
	}
	otherReader, _, err := driver.Open(ctx, other.Key)
	if err != nil {
		t.Fatal("open separate workspace after corruption:", err)
	}
	otherBytes, readErr := io.ReadAll(otherReader)
	closeErr = otherReader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(otherBytes, payload) {
		t.Fatalf("other workspace object was affected: read=%v close=%v", readErr, closeErr)
	}
	if err := driver.Delete(ctx, info.Key); err != nil {
		t.Fatal("delete fixture object:", err)
	}
	if err := driver.Delete(ctx, other.Key); err != nil {
		t.Fatal("delete other fixture object:", err)
	}
	entries, err := os.ReadDir(staging)
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging cleanup: %d entries, error=%v", len(entries), err)
	}
}
