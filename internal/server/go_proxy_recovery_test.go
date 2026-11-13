package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"private-registry/internal/artifacts"
	"private-registry/internal/auth"
	"private-registry/internal/backup"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/gomod"
	"private-registry/internal/repositories"
	"private-registry/internal/secrets"
	"private-registry/internal/spikes/sqlitebackup"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
)

type goRecoveryStage struct{ *os.File }

func (s goRecoveryStage) Close() error {
	return errors.Join(s.File.Close(), os.Remove(s.Name()))
}

// This uses an isolated synthetic handler and a newly generated test key. It
// does not start registry serve or prove recovery of the installation's keys.
func exerciseRecoveredGoClient(t *testing.T, ctx context.Context, source authHTTPFixture, objects storage.Driver, workspaceID, repositoryID, readerID, oldBearer, modulePath, version string) {
	t.Helper()
	root := t.TempDir()
	snapshotPath := filepath.Join(root, "snapshot.sqlite")
	if _, err := sqlitebackup.Snapshot(ctx, source.db, snapshotPath, sqlitebackup.Options{PagesPerStep: 16}); err != nil {
		t.Fatal(err)
	}
	plain, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	var installationID string
	if err := source.db.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&installationID); err != nil {
		t.Fatal(err)
	}
	uri := url.URL{Scheme: "file", Path: snapshotPath}
	query := uri.Query()
	query.Set("mode", "ro")
	uri.RawQuery = query.Encode()
	snapshotDB, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshotDB.Close() })
	tx, err := snapshotDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	inventory, inventoryErr := backup.InventoryGo(ctx, tx, 10, 10)
	rollbackErr := tx.Rollback()
	if inventoryErr != nil || rollbackErr != nil || len(inventory) != 3 {
		t.Fatalf("Go snapshot inventory count=%d err=%v rollback=%v", len(inventory), inventoryErr, rollbackErr)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(plain)
	trust := backup.GenericSetRecovery{Signer: public, InstallationID: installationID, BackupID: uuid.NewString(), SnapshotSHA256: hex.EncodeToString(digest[:]), Inventory: inventory}
	genericSet, err := backup.SignGenericSet(backup.GenericSet{Version: 1, InstallationID: installationID, BackupID: trust.BackupID, SnapshotSHA256: trust.SnapshotSHA256, Objects: []backup.ObjectReceipt{}}, private)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := storage.NewFileSystem(filepath.Join(root, "backup"))
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	newStage := func() (backup.RecoveryStage, error) {
		file, err := os.CreateTemp(staging, "owned-*")
		if err != nil {
			return nil, err
		}
		return goRecoveryStage{File: file}, nil
	}
	goSet, err := backup.CaptureGoSet(ctx, trust, objects, remote, identity.Recipient(), private, 1<<20, newStage)
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if _, err := backup.EncryptSnapshot(ctx, bytes.NewReader(plain), &encrypted, 64<<20, 65<<20, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	sources := make([]backup.RecoveryObjectSource, 0, len(goSet.Receipts))
	for _, envelope := range goSet.Receipts {
		receipt, err := backup.VerifyObjectReceipt(envelope, public, installationID, trust.BackupID)
		if err != nil {
			t.Fatal(err)
		}
		key := storage.ObjectKey{WorkspaceID: receipt.WorkspaceID, SHA256: receipt.CipherSHA256}
		sources = append(sources, backup.RecoveryObjectSource{Receipt: envelope, Open: func(ctx context.Context) (io.ReadCloser, error) {
			reader, _, err := remote.Open(ctx, key)
			return reader, err
		}})
	}
	parent := filepath.Join(root, "recovery")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	prepared, err := backup.PrepareEncryptedSQLiteGoRecovery(ctx, bytes.NewReader(encrypted.Bytes()), 65<<20, 64<<20, 10, 10, genericSet, trust, goSet.Set, trust, parent, "isolated", nil, sources, identity, newStage)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(prepared.DatabasePath)
	if _, err := os.Stat(filepath.Join(dir, "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal("recovery marker missing:", err)
	}
	cfg := config.Config{DataDir: dir, DatabaseDriver: config.SQLite, DatabaseDSN: prepared.DatabasePath, DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repos, err := repositories.New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repos.VerifyPersonalReadToken(ctx, oldBearer, workspaceID, repositoryID); !errors.Is(err, repositories.ErrPersonalTokenUnavailable) {
		t.Fatalf("recovered old token accepted: %v", err)
	}
	newToken, err := repos.IssuePersonalReadToken(ctx, readerID, workspaceID, repositoryID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(root, "test-key")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "master.key")
	if err := secrets.InitializeMasterKey(keyPath, dir); err != nil {
		t.Fatal(err)
	}
	key, err := secrets.LoadMasterKeyFile(keyPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	authService, err := auth.New(db, config.SQLite, &key)
	if err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	recoveredObjects, err := storage.NewFileSystem(filepath.Join(dir, "object-store"))
	if err != nil {
		t.Fatal(err)
	}
	artifactService, err := artifacts.New(db, config.SQLite, repos, recoveredObjects, artifacts.Options{MaxUploadBytes: 1 << 20, MaxConcurrentUploads: 1})
	if err != nil {
		t.Fatal(err)
	}
	modules, err := gomod.NewService(db, config.SQLite, repos, recoveredObjects, gomod.Options{StagingDirectory: staging, MaxZipBytes: 1 << 20, MaxFiles: 100, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	recovered := authHTTPFixture{db: db, service: authService, workspaceService: workspaceService, repositoryService: repos, artifactService: artifactService}
	exerciseRealGoClient(t, ctx, recovered, modules, newToken.Bearer, workspaceID, repositoryID, modulePath, version)
}
