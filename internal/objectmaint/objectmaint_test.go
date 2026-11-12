package objectmaint_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"private-registry/internal/bootstrap"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/objectmaint"
	"private-registry/internal/oci"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
)

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func TestSQLiteObjectCollection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: dataDir, DatabaseDriver: config.SQLite, DatabaseDSN: filepath.Join(dataDir, "registry.sqlite"), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	ExerciseObjectCollection(t, ctx, db, config.SQLite)
}

// ExerciseObjectCollection is shared with the PostgreSQL test.
func ExerciseObjectCollection(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver) {
	t.Helper()
	owner, err := bootstrap.CreateFirstAdmin(ctx, db, driver, bootstrap.AdminInput{LoginName: "objects.owner", DisplayName: "Objects", Email: "objects@example.invalid", Password: []byte("synthetic-objects-password-never-reuse"), OperatorLabel: "synthetic-test-operator"})
	if err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "objects", "Objects")
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
	root := t.TempDir()
	store, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := oci.New(db, driver, repos, store, oci.Options{StagingDirectory: filepath.Join(root, "staging"), MaxBlobBytes: 1 << 20, MaxUploads: 4})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := service.Authorize(ctx, token.Bearer, workspace.ID, repository.ID)
	if err != nil {
		t.Fatal(err)
	}
	referenced := []byte("referenced through an OCI repository")
	id, err := service.StartUpload(writer, workspace.ID, repository.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.FinishUpload(ctx, writer, workspace.ID, repository.ID, id, "sha256:"+digestOf(referenced), bytes.NewReader(referenced)); err != nil {
		t.Fatal(err)
	}
	put := func(content []byte, age time.Duration) storage.ObjectKey {
		t.Helper()
		info, err := store.Put(ctx, workspace.ID, bytes.NewReader(content), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "objects", "objects", "workspaces", workspace.ID, info.Key.SHA256[:2], info.Key.SHA256)
		when := time.Now().Add(-age)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatal(err)
		}
		return info.Key
	}
	orphan := put([]byte("orphaned after a failed commit"), 48*time.Hour)
	recent := put([]byte("written just before serve stopped"), time.Minute)
	kept := storage.ObjectKey{WorkspaceID: workspace.ID, SHA256: digestOf(referenced)}
	path := filepath.Join(root, "objects", "objects", "workspaces", workspace.ID, kept.SHA256[:2], kept.SHA256)
	if err := os.Chtimes(path, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}

	report, err := objectmaint.Collect(ctx, db, driver, store, time.Now(), 24*time.Hour, false)
	if err != nil || report.Scanned != 3 || report.Referenced != 1 || report.TooRecent != 1 || report.Unreferenced != 1 || report.Deleted != 0 {
		t.Fatalf("dry run: %+v %v", report, err)
	}
	open := func(key storage.ObjectKey) error {
		reader, _, err := store.Open(ctx, key)
		if err == nil {
			_ = reader.Close()
		}
		return err
	}
	if err := open(orphan); err != nil {
		t.Fatalf("dry run deleted an object: %v", err)
	}
	report, err = objectmaint.Collect(ctx, db, driver, store, time.Now(), 24*time.Hour, true)
	if err != nil || report.Deleted != 1 || report.DeletedBytes != int64(len("orphaned after a failed commit")) {
		t.Fatalf("apply: %+v %v", report, err)
	}
	if err := open(orphan); err == nil {
		t.Fatal("unreferenced object survived collection")
	}
	for _, key := range []storage.ObjectKey{kept, recent} {
		if err := open(key); err != nil {
			t.Fatalf("collection deleted a referenced or recent object: %v", err)
		}
	}
	if _, err := objectmaint.Collect(ctx, db, driver, store, time.Now(), time.Minute, true); err == nil {
		t.Fatal("a grace shorter than an hour was accepted")
	}
	// A schema this package does not know might reference objects elsewhere.
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_migration_checksums (version_id, checksum) VALUES (`+map[config.DatabaseDriver]string{config.SQLite: "?, ?", config.Postgres: "$1, $2"}[driver]+`)`, objectmaint.KnownSchemaVersion+1, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := objectmaint.Collect(ctx, db, driver, store, time.Now(), 24*time.Hour, true); err == nil {
		t.Fatal("collection ran against an unknown schema")
	}

	// Copying into another store is complete, verified and repeatable.
	target, err := storage.NewFileSystem(filepath.Join(root, "target"))
	if err != nil {
		t.Fatal(err)
	}
	copied, err := objectmaint.Copy(ctx, store, target, 1<<20, nil)
	if err != nil || copied.Copied != 2 {
		t.Fatalf("copy: %+v %v", copied, err)
	}
	if again, err := objectmaint.Copy(ctx, store, target, 1<<20, nil); err != nil || again.Copied != 2 {
		t.Fatalf("repeated copy: %+v %v", again, err)
	}
	for _, key := range []storage.ObjectKey{kept, recent} {
		reader, _, err := target.Open(ctx, key)
		if err != nil {
			t.Fatalf("copied object unreadable: %v", err)
		}
		_ = reader.Close()
	}
	// A corrupted source object stops the copy instead of being propagated.
	corruptPath := filepath.Join(root, "objects", "objects", "workspaces", workspace.ID, recent.SHA256[:2], recent.SHA256)
	if err := os.WriteFile(corruptPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := storage.NewFileSystem(filepath.Join(root, "other"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objectmaint.Copy(ctx, store, other, 1<<20, nil); err == nil {
		t.Fatal("a corrupted object was copied")
	}
}

func TestInstanceLockExcludesASecondHolder(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the instance lock is Linux only")
	}
	dir := filepath.Join(t.TempDir(), "data")
	first, err := objectmaint.AcquireInstanceLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objectmaint.AcquireInstanceLock(dir); !errors.Is(err, objectmaint.ErrInstanceRunning) {
		t.Fatalf("second holder: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := objectmaint.AcquireInstanceLock(dir)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	_ = second.Release()
}
