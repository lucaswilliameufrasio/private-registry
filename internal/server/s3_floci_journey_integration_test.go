//go:build integration && linux

package server

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"private-registry/internal/artifacts"
	"private-registry/internal/config"
	"private-registry/internal/spikes/remotebackup"
	"private-registry/internal/spikes/testinfra"
	"private-registry/internal/storage"
)

func TestS3FlociGenericHTTPJourney(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
	client, err := remotebackup.NewClient(floci.Endpoint, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	bucket := "synthetic-" + uuid.NewString()
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	objectStore, err := storage.NewS3(client, bucket, "test", filepath.Join(t.TempDir(), "stage"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	bounded, err := storage.NewBoundedDriver(objectStore, 2)
	if err != nil {
		t.Fatal(err)
	}
	driver, err := storage.NewDeadlineDriver(bounded, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newAuthHTTPFixture(t)
	fixture.artifactService, err = artifacts.New(fixture.db, config.SQLite, fixture.repositoryService, driver, artifacts.Options{MaxUploadBytes: 1 << 20, MaxConcurrentUploads: 2})
	if err != nil {
		t.Fatal(err)
	}
	exerciseAuthHTTPGenericArtifactPublication(t, fixture)
}
