//go:build integration

package artifacts

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/spikes/remotebackup"
	"private-registry/internal/spikes/testinfra"
	"private-registry/internal/storage"
)

func TestNPMReceiptUsesIsolatedFloci(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	floci, err := testinfra.StartFloci(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := floci.Stop(); err != nil {
			t.Errorf("stop Floci fixture: %v", err)
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
			t.Fatal("Floci fixture did not become ready")
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
	objects, err := storage.NewS3(client, bucket, "synthetic", filepath.Join(t.TempDir(), "staging"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newArtifactFixture(t)
	exerciseNPMReceiptValidatesAndStores(t, fixture.db, config.SQLite, fixture.repositoryService, objects, fixture.workspaceID, fixture.userIDs["owner"], fixture.userIDs["publisher"])
}
