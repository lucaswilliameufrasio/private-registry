//go:build integration && linux

package fullbackup_test

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"private-registry/internal/bootstrap"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/fullbackup"
	"private-registry/internal/migrations"
	"private-registry/internal/oci"
	"private-registry/internal/repositories"
	"private-registry/internal/spikes/remotebackup"
	spikesinfra "private-registry/internal/spikes/testinfra"
	"private-registry/internal/storage"
	"private-registry/internal/testinfra"
	"private-registry/internal/workspaces"
)

func startBucket(t *testing.T, ctx context.Context) (fullbackup.Bucket, *s3.Client) {
	t.Helper()
	floci, err := spikesinfra.StartFloci(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := floci.Stop(); err != nil {
			t.Error(err)
		}
	})
	for {
		response, err := (&http.Client{Timeout: time.Second}).Get(floci.Endpoint + "/health")
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
	name := "synthetic-" + uuid.NewString()
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(name)}); err != nil {
		t.Fatal(err)
	}
	return fullbackup.Bucket{Client: client, Name: name, Prefix: "registry/backups"}, client
}

// seed publishes one OCI image so the database references stored objects.
func seed(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver, store storage.Driver, staging string) (string, [][]byte) {
	t.Helper()
	owner, err := bootstrap.CreateFirstAdmin(ctx, db, driver, bootstrap.AdminInput{LoginName: "backup.owner", DisplayName: "Backup", Email: "backup@example.invalid", Password: []byte("synthetic-backup-password-never-reuse"), OperatorLabel: "synthetic-test-operator"})
	if err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "backup", "Backup")
	if err != nil {
		t.Fatal(err)
	}
	repos, err := repositories.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	if err := repos.EnableFormatCreation(repositories.FormatOCI); err != nil {
		t.Fatal(err)
	}
	repository, err := repos.CreateWithFormat(ctx, owner, workspace.ID, "images", "Images", repositories.FormatOCI)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []repositories.GrantRole{repositories.GrantReader, repositories.GrantPublisher} {
		if _, err := repos.GrantRepositoryRole(ctx, owner, workspace.ID, repository.ID, owner, role); err != nil {
			t.Fatal(err)
		}
	}
	token, err := repos.IssueOCIWriteToken(ctx, owner, workspace.ID, repository.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := oci.New(db, driver, repos, store, oci.Options{StagingDirectory: staging, MaxBlobBytes: 1 << 20, MaxUploads: 4})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := service.Authorize(ctx, token.Bearer, workspace.ID, repository.ID)
	if err != nil {
		t.Fatal(err)
	}
	contents := [][]byte{[]byte(`{"os":"linux"}`), bytes.Repeat([]byte("backed up layer "), 2000)}
	for _, content := range contents {
		id, err := service.StartUpload(writer, workspace.ID, repository.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.FinishUpload(ctx, writer, workspace.ID, repository.ID, id, "sha256:"+digest(content), bytes.NewReader(content)); err != nil {
			t.Fatal(err)
		}
	}
	return workspace.ID, contents
}

func identities(t *testing.T) (*age.X25519Identity, *age.X25519Identity) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return identity, other
}

func privateDir(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSQLiteBackupVerifyRestore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	bucket, client := startBucket(t, ctx)
	identity, other := identities(t)
	dataDir := privateDir(t, "data")
	cfg := config.Config{DataDir: dataDir, DatabaseDriver: config.SQLite, DatabaseDSN: filepath.Join(dataDir, "registry.sqlite"), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewFileSystem(filepath.Join(dataDir, "object-store"))
	if err != nil {
		t.Fatal(err)
	}
	workspace, contents := seed(t, ctx, db, config.SQLite, store, filepath.Join(dataDir, "oci-staging"))
	options := fullbackup.Options{DB: db, Driver: config.SQLite, Store: store, Bucket: bucket, Recipient: identity.Recipient(), Staging: filepath.Join(dataDir, "backup-staging"), Retain: 2}
	first, err := fullbackup.Run(ctx, options)
	if err != nil || first.Objects != 2 || first.ObjectsUploaded != 2 {
		t.Fatalf("first backup: %+v %v", first, err)
	}
	// Objects are content-addressed and shared: a second backup uploads none.
	options.Now = time.Now().Add(time.Second)
	second, err := fullbackup.Run(ctx, options)
	if err != nil || second.ObjectsUploaded != 0 || second.ID == first.ID {
		t.Fatalf("second backup: %+v %v", second, err)
	}
	// Nothing in the bucket is readable without the identity.
	listed, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket.Name)})
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range listed.Contents {
		if strings.HasSuffix(*object.Key, ".json") {
			continue
		}
		body, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket.Name), Key: object.Key})
		if err != nil {
			t.Fatal(err)
		}
		var raw bytes.Buffer
		_, _ = raw.ReadFrom(body.Body)
		_ = body.Body.Close()
		if !bytes.HasPrefix(raw.Bytes(), []byte("age-encryption.org/v1")) || bytes.Contains(raw.Bytes(), []byte("backed up layer")) || bytes.Contains(raw.Bytes(), []byte("SQLite format")) {
			t.Fatalf("%s is not age-encrypted", *object.Key)
		}
	}

	verifyStaging := privateDir(t, "verify")
	if report, err := fullbackup.Verify(ctx, bucket, identity, "", verifyStaging, ""); err != nil || report.ID != second.ID || report.Objects != 2 {
		t.Fatalf("verify newest: %+v %v", report, err)
	}
	if _, err := fullbackup.Verify(ctx, bucket, identity, first.ID, verifyStaging, ""); err != nil {
		t.Fatalf("verify first: %v", err)
	}
	if _, err := fullbackup.Verify(ctx, bucket, other, "", verifyStaging, ""); err == nil {
		t.Fatal("verification succeeded with the wrong identity")
	}
	if entries, _ := os.ReadDir(verifyStaging); len(entries) != 0 {
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("verification left staged files: %v", names)
	}

	// Restore into an empty installation and compare.
	target := privateDir(t, "restored")
	targetStore, err := storage.NewFileSystem(filepath.Join(target, "object-store"))
	if err != nil {
		t.Fatal(err)
	}
	restoredPath := filepath.Join(target, "registry.sqlite")
	report, err := fullbackup.Restore(ctx, fullbackup.RestoreOptions{Bucket: bucket, Identity: identity, Staging: filepath.Join(target, "staging"), Driver: config.SQLite, SQLite: restoredPath, Store: targetStore})
	if err != nil || report.ObjectsRestored != 2 {
		t.Fatalf("restore: %+v %v", report, err)
	}
	if _, err := fullbackup.Restore(ctx, fullbackup.RestoreOptions{Bucket: bucket, Identity: identity, Staging: filepath.Join(target, "staging"), Driver: config.SQLite, SQLite: restoredPath, Store: targetStore}); err == nil {
		t.Fatal("restore overwrote an existing database")
	}
	restored, err := sql.Open("sqlite", restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var blobs int
	if err := restored.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_oci_blobs`).Scan(&blobs); err != nil || blobs != 2 {
		t.Fatalf("restored database: %d %v", blobs, err)
	}
	for _, content := range contents {
		reader, _, err := targetStore.Open(ctx, storage.ObjectKey{WorkspaceID: workspace, SHA256: digest(content)})
		if err != nil {
			t.Fatalf("restored object: %v", err)
		}
		var got bytes.Buffer
		_, _ = got.ReadFrom(reader)
		_ = reader.Close()
		if !bytes.Equal(got.Bytes(), content) {
			t.Fatal("restored object differs")
		}
	}

	// Retention keeps the newest two complete backups and the objects they
	// list; a third backup removes the first.
	options.Now = time.Now().Add(2 * time.Second)
	third, err := fullbackup.Run(ctx, options)
	if err != nil || len(third.Removed) != 1 || third.Removed[0] != first.ID {
		t.Fatalf("retention: %+v %v", third, err)
	}
	ids, err := fullbackup.ListBackups(ctx, bucket)
	if err != nil || len(ids) != 2 || ids[0] != third.ID || ids[1] != second.ID {
		t.Fatalf("backups after retention: %v %v", ids, err)
	}

	// A tampered object is caught by verification.
	key := "registry/backups/objects/" + workspace + "/" + digest(contents[1]) + ".age"
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket.Name), Key: aws.String(key), Body: strings.NewReader("tampered")}); err != nil {
		t.Fatal(err)
	}
	if _, err := fullbackup.Verify(ctx, bucket, identity, "", verifyStaging, ""); err == nil {
		t.Fatal("verification accepted a tampered object")
	}
}

func TestPostgresBackupVerifyRestore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	bucket, _ := startBucket(t, ctx)
	identity, _ := identities(t)
	open := func() (*sql.DB, string) {
		t.Helper()
		fixture, err := testinfra.StartPostgres(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := fixture.Stop(); err != nil {
				t.Error(err)
			}
		})
		cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
		db, err := database.Open(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db, fixture.DSN()
	}
	source, sourceDSN := open()
	cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: sourceDSN, DatabaseMaxOpenConns: 4}
	if _, err := migrations.Migrate(ctx, source, cfg); err != nil {
		t.Fatal(err)
	}
	dataDir := privateDir(t, "data")
	store, err := storage.NewFileSystem(filepath.Join(dataDir, "object-store"))
	if err != nil {
		t.Fatal(err)
	}
	workspace, contents := seed(t, ctx, source, config.Postgres, store, filepath.Join(dataDir, "oci-staging"))
	report, err := fullbackup.Run(ctx, fullbackup.Options{DB: source, Driver: config.Postgres, DSN: sourceDSN, Store: store, Bucket: bucket, Recipient: identity.Recipient(), Staging: filepath.Join(dataDir, "backup-staging"), Retain: 3})
	if err != nil || report.Objects != 2 {
		t.Fatalf("PostgreSQL backup: %+v %v", report, err)
	}
	if _, err := fullbackup.Verify(ctx, bucket, identity, "", privateDir(t, "verify"), ""); err != nil {
		t.Fatalf("PostgreSQL verify: %v", err)
	}
	target, targetDSN := open()
	targetStore, err := storage.NewFileSystem(filepath.Join(privateDir(t, "target"), "object-store"))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := fullbackup.Restore(ctx, fullbackup.RestoreOptions{Bucket: bucket, Identity: identity, Staging: privateDir(t, "restore-staging"), Driver: config.Postgres, DB: target, DSN: targetDSN, Store: targetStore})
	if err != nil || restored.ObjectsRestored != 2 {
		t.Fatalf("PostgreSQL restore: %+v %v", restored, err)
	}
	var sourceID, targetID string
	if err := source.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation`).Scan(&sourceID); err != nil {
		t.Fatal(err)
	}
	if err := target.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation`).Scan(&targetID); err != nil || targetID != sourceID {
		t.Fatalf("restored installation: %q %v", targetID, err)
	}
	if err := migrations.VerifyCurrent(ctx, target, config.Postgres, targetID); err != nil {
		t.Fatalf("restored schema does not verify: %v", err)
	}
	for _, content := range contents {
		reader, _, err := targetStore.Open(ctx, storage.ObjectKey{WorkspaceID: workspace, SHA256: digest(content)})
		if err != nil {
			t.Fatalf("restored object: %v", err)
		}
		_ = reader.Close()
	}
	if _, err := fullbackup.Restore(ctx, fullbackup.RestoreOptions{Bucket: bucket, Identity: identity, Staging: privateDir(t, "again"), Driver: config.Postgres, DB: target, DSN: targetDSN, Store: targetStore}); err == nil {
		t.Fatal("restore into a non-empty PostgreSQL database was accepted")
	}
}
