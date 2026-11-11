package oci_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"private-registry/internal/backup"
	"private-registry/internal/bootstrap"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/oci"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
)

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestSQLiteOCIRegistry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: dataDir, DatabaseDriver: config.SQLite, DatabaseMaxOpenConns: 4}
	cfg.DatabaseDSN = filepath.Join(cfg.DataDir, "registry.sqlite")
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	exerciseOCIRegistry(t, ctx, db, config.SQLite)
}

// exerciseOCIRegistry runs the same publication, read, isolation and
// revocation checks on either database engine.
func exerciseOCIRegistry(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver) {
	t.Helper()
	owner, err := bootstrap.CreateFirstAdmin(ctx, db, driver, bootstrap.AdminInput{LoginName: "oci.owner", DisplayName: "Synthetic OCI Owner", Email: "oci@example.invalid", Password: []byte("synthetic-oci-password-never-reuse"), OperatorLabel: "synthetic-test-operator"})
	if err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "oci-engine", "OCI engine")
	if err != nil {
		t.Fatal(err)
	}
	repos, err := repositories.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repos.CreateWithFormat(ctx, owner, workspace.ID, "disabled", "Disabled", repositories.FormatOCI); !errors.Is(err, repositories.ErrInvalidFormat) {
		t.Fatalf("OCI repository created before the format was enabled: %v", err)
	}
	if err := repos.EnableFormatCreation(repositories.FormatOCI); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := oci.New(db, driver, repos, store, oci.Options{StagingDirectory: filepath.Join(root, "staging"), MaxBlobBytes: 1 << 20, MaxUploads: 2})
	if err != nil {
		t.Fatal(err)
	}
	setup := func(slug string) (string, oci.Principal, oci.Principal) {
		t.Helper()
		repository, err := repos.CreateWithFormat(ctx, owner, workspace.ID, slug, slug, repositories.FormatOCI)
		if err != nil {
			t.Fatal(err)
		}
		for _, role := range []repositories.GrantRole{repositories.GrantReader, repositories.GrantPublisher} {
			if _, err := repos.GrantRepositoryRole(ctx, owner, workspace.ID, repository.ID, owner, role); err != nil {
				t.Fatal(err)
			}
		}
		write, err := repos.IssueOCIWriteToken(ctx, owner, workspace.ID, repository.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		read, err := repos.IssuePersonalReadToken(ctx, owner, workspace.ID, repository.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		writer, err := service.Authorize(ctx, write.Bearer, workspace.ID, repository.ID)
		if err != nil || !writer.CanWrite || !writer.CanRead {
			t.Fatalf("write token authorization: %+v %v", writer, err)
		}
		reader, err := service.Authorize(ctx, read.Bearer, workspace.ID, repository.ID)
		if err != nil || reader.CanWrite || !reader.CanRead {
			t.Fatalf("read token authorization: %+v %v", reader, err)
		}
		return repository.ID, writer, reader
	}
	repository, writer, reader := setup("images")
	push := func(repository string, principal oci.Principal, content []byte) string {
		t.Helper()
		id, err := service.StartUpload(principal, workspace.ID, repository)
		if err != nil {
			t.Fatal(err)
		}
		half := len(content) / 2
		if size, err := service.AppendUpload(ctx, principal, workspace.ID, repository, id, 0, bytes.NewReader(content[:half])); err != nil || size != int64(half) {
			t.Fatalf("append: size=%d err=%v", size, err)
		}
		if size, err := service.FinishUpload(ctx, principal, workspace.ID, repository, id, digestOf(content), bytes.NewReader(content[half:])); err != nil || size != int64(len(content)) {
			t.Fatalf("finish: size=%d err=%v", size, err)
		}
		return digestOf(content)
	}
	config1 := []byte(`{"architecture":"arm64","os":"linux"}`)
	layer := bytes.Repeat([]byte{0, 1, 2, 3, 255}, 9000)
	configDigest := push(repository, writer, config1)
	layerDigest := push(repository, writer, layer)
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"%s","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"%s","size":%d}]}`, oci.MediaTypeOCIManifest, configDigest, len(config1), layerDigest, len(layer)))

	if _, err := service.StartUpload(reader, workspace.ID, repository); !errors.Is(err, oci.ErrUnauthorized) {
		t.Fatalf("read principal started an upload: %v", err)
	}
	if _, err := service.PutManifest(ctx, reader, workspace.ID, repository, "app", "v1", oci.MediaTypeOCIManifest, manifest); !errors.Is(err, oci.ErrUnauthorized) {
		t.Fatalf("read principal pushed a manifest: %v", err)
	}
	digest, err := service.PutManifest(ctx, writer, workspace.ID, repository, "app", "v1", oci.MediaTypeOCIManifest, manifest)
	if err != nil || digest != digestOf(manifest) {
		t.Fatalf("manifest push: %q %v", digest, err)
	}
	if again, err := service.PutManifest(ctx, writer, workspace.ID, repository, "app", "v1", oci.MediaTypeOCIManifest, manifest); err != nil || again != digest {
		t.Fatalf("repeated manifest push is not idempotent: %v", err)
	}
	index := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"%s","manifests":[{"mediaType":"%s","digest":"%s","size":%d}]}`, oci.MediaTypeOCIIndex, oci.MediaTypeOCIManifest, digest, len(manifest)))
	if _, err := service.PutManifest(ctx, writer, workspace.ID, repository, "app", "multi", oci.MediaTypeOCIIndex, index); err != nil {
		t.Fatalf("index push: %v", err)
	}
	for _, reference := range []string{"v1", digest} {
		got, err := service.GetManifest(ctx, repository, "app", reference)
		if err != nil || got.Digest != digest || got.MediaType != oci.MediaTypeOCIManifest || !bytes.Equal(got.Content, manifest) {
			t.Fatalf("manifest read by %s: %v", reference, err)
		}
	}
	if tags, err := service.ListTags(ctx, repository, "app", "", 10); err != nil || fmt.Sprint(tags) != "[multi v1]" {
		t.Fatalf("tags: %v %v", tags, err)
	}
	if tags, err := service.ListTags(ctx, repository, "app", "multi", 10); err != nil || fmt.Sprint(tags) != "[v1]" {
		t.Fatalf("tags after cursor: %v %v", tags, err)
	}
	blob, size, err := service.OpenBlob(ctx, workspace.ID, repository, layerDigest)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := io.ReadAll(blob)
	if closeErr := blob.Close(); err != nil || closeErr != nil || size != int64(len(layer)) || !bytes.Equal(stored, layer) {
		t.Fatalf("blob read: size=%d err=%v close=%v", size, err, closeErr)
	}
	var references int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_oci_manifest_references`).Scan(&references); err != nil || references != 3 {
		t.Fatalf("reference edges: %d %v", references, err)
	}

	// Another repository of the same workspace shares the object store but
	// not blob membership.
	other, otherWriter, _ := setup("other")
	if _, err := service.StatBlob(ctx, other, layerDigest); !errors.Is(err, oci.ErrBlobUnknown) {
		t.Fatalf("blob visible in another repository: %v", err)
	}
	if _, err := service.PutManifest(ctx, otherWriter, workspace.ID, other, "app", "v1", oci.MediaTypeOCIManifest, manifest); !errors.Is(err, oci.ErrManifestBlob) {
		t.Fatalf("manifest accepted with blobs of another repository: %v", err)
	}
	if _, err := service.PutManifest(ctx, otherWriter, workspace.ID, repository, "app", "hijack", oci.MediaTypeOCIManifest, manifest); !errors.Is(err, oci.ErrUnauthorized) {
		t.Fatalf("token of another repository committed a manifest: %v", err)
	}
	if _, err := service.GetManifest(ctx, other, "app", digest); !errors.Is(err, oci.ErrManifestUnknown) {
		t.Fatalf("manifest visible in another repository: %v", err)
	}

	// Capacity: two live sessions are the configured maximum.
	first, err := service.StartUpload(writer, workspace.ID, repository)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.StartUpload(writer, workspace.ID, repository)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.StartUpload(writer, workspace.ID, repository); !errors.Is(err, oci.ErrBusy) {
		t.Fatalf("upload capacity not enforced: %v", err)
	}
	if err := service.CancelUpload(writer, workspace.ID, repository, second); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AppendUpload(ctx, writer, workspace.ID, repository, first, -1, bytes.NewReader(bytes.Repeat([]byte("x"), (1<<20)+1))); !errors.Is(err, oci.ErrTooLarge) {
		t.Fatalf("oversized chunk: %v", err)
	}
	if size, err := service.UploadSize(writer, workspace.ID, repository, first); err != nil || size != 0 {
		t.Fatalf("rejected chunk left bytes behind: size=%d err=%v", size, err)
	}

	// Revocation between upload and commit: the transaction that would
	// record the blob or the manifest rechecks the grant and refuses.
	if _, err := service.AppendUpload(ctx, writer, workspace.ID, repository, first, 0, bytes.NewReader([]byte("pending"))); err != nil {
		t.Fatal(err)
	}
	if err := repos.RevokeRepositoryRole(ctx, owner, workspace.ID, repository, owner, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := service.FinishUpload(ctx, writer, workspace.ID, repository, first, digestOf([]byte("pending")), nil); !errors.Is(err, oci.ErrUnauthorized) {
		t.Fatalf("blob recorded after revocation: %v", err)
	}
	if _, err := service.StatBlob(ctx, repository, digestOf([]byte("pending"))); !errors.Is(err, oci.ErrBlobUnknown) {
		t.Fatalf("revoked upload became visible: %v", err)
	}
	if _, err := service.PutManifest(ctx, writer, workspace.ID, repository, "app", "late", oci.MediaTypeOCIManifest, manifest); !errors.Is(err, oci.ErrUnauthorized) {
		t.Fatalf("manifest committed after revocation: %v", err)
	}
	if _, err := service.GetManifest(ctx, repository, "app", "late"); !errors.Is(err, oci.ErrManifestUnknown) {
		t.Fatalf("tag exists after revoked commit: %v", err)
	}

	// Recovery does not capture OCI blobs yet, so it must refuse this
	// installation instead of promoting manifests without their content.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, recoveryErr := backup.InvalidateRestoredCredentials(ctx, tx, driver, time.Now())
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if recoveryErr == nil || !strings.Contains(recoveryErr.Error(), "OCI content") {
		t.Fatalf("recovery accepted an installation with OCI content: %v", recoveryErr)
	}
}
