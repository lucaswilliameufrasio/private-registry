//go:build integration

package gomod

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
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/spikes/remotebackup"
	"private-registry/internal/spikes/testinfra"
	"private-registry/internal/storage"
)

func TestSQLiteGoRecoveryFromIsolatedFloci(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	fixture, err := testinfra.StartFloci(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Error(err)
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
			t.Fatal("isolated Floci did not become ready")
		case <-time.After(50 * time.Millisecond):
		}
	}
	client, err := remotebackup.NewClient(fixture.Endpoint, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	bucket := "synthetic-" + uuid.NewString()
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	remote, err := storage.NewS3(client, bucket, "isolated-backup", filepath.Join(root, "remote-staging"), 65<<20)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: filepath.Join(root, "data"), DatabaseDriver: config.SQLite, DatabaseDSN: filepath.Join(root, "data", "registry.sqlite"), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	exerciseModulePublication(t, ctx, db, config.SQLite, root, remote)
}
