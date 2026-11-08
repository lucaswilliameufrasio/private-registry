//go:build linux && integration

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"private-registry/internal/backup"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/spikes/sqlitebackup"
)

// This test proves only the exercised SQLite startup and health path in a
// throwaway network namespace. It does not validate installation, recovery,
// all package formats, privileged configuration, or production egress policy.
func TestOfflineSQLiteStartupInIsolatedNetworkNamespace(t *testing.T) {
	if os.Getenv("REGISTRY_OFFLINE_TEST_CHILD") == "1" {
		exerciseOfflineSQLiteStartup(t)
		return
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatal("offline test requires bubblewrap:", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// No host firewall, routes, interfaces, privileges or settings change.
	command := exec.CommandContext(ctx, bwrap, "--die-with-parent", "--unshare-user", "--uid", "0", "--gid", "0", "--unshare-net", "--tmpfs", "/", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/work", "--ro-bind", executable, "/testbin", "--chdir", "/work", "--", "/testbin", "-test.run=^TestOfflineSQLiteStartupInIsolatedNetworkNamespace$", "-test.count=1", "-test.timeout=45s")
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/work", "TMPDIR=/work", "REGISTRY_OFFLINE_TEST_CHILD=1", "REGISTRY_OFFLINE_TEST_ROOT=/work", "GOMAXPROCS=4"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated SQLite startup failed: %v\n%s", err, output)
	}
}

func exerciseOfflineSQLiteStartup(t *testing.T) {
	t.Helper()
	root := os.Getenv("REGISTRY_OFFLINE_TEST_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("offline fixture root is invalid")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagLoopback == 0 || interfaces[0].Flags&net.FlagUp == 0 {
		t.Fatal("offline fixture is not isolated to an active loopback interface")
	}
	keys := filepath.Join(root, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGISTRY_DATA_DIR", filepath.Join(root, "data"))
	t.Setenv("REGISTRY_DATABASE_DRIVER", "sqlite")
	t.Setenv("REGISTRY_MASTER_KEY_FILE", filepath.Join(keys, "master.key"))
	t.Setenv("REGISTRY_CANONICAL_ORIGIN", "https://registry.example")
	t.Setenv("REGISTRY_ASSET_ORIGIN", "https://assets.example")
	t.Setenv("REGISTRY_TRUSTED_PROXIES", "127.0.0.1")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REGISTRY_LISTEN_ADDRESS", address)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(ctx, []string{"migrate"}, logger); err != nil {
		t.Fatal("offline migration:", err)
	}
	if err := run(ctx, []string{"init-master-key"}, logger); err != nil {
		t.Fatal("offline master-key initialization:", err)
	}
	serverCtx, stopServer := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() {
		result <- run(serverCtx, []string{"serve"}, logger)
	}()
	defer func() {
		stopServer()
		if err := <-result; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("stop offline server: %v", err)
		}
	}()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	ready := false
	for !ready {
		response, err := client.Get("http://" + address + "/readyz")
		if err == nil {
			ready = response.StatusCode == http.StatusNoContent
			_ = response.Body.Close()
		}
		if !ready {
			select {
			case <-ctx.Done():
				t.Fatal("offline server did not become ready")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	exerciseOfflineSnapshotRecovery(t, ctx, root)
	probe, err := net.DialTimeout("tcp", "192.0.2.1:443", time.Second)
	if err == nil {
		_ = probe.Close()
		t.Fatal("isolated network unexpectedly allowed an external connection")
	}
}

type offlineRecoveryStage struct{ *os.File }

func (s offlineRecoveryStage) Close() error {
	name := s.Name()
	return errors.Join(s.File.Close(), os.Remove(name))
}

func exerciseOfflineSnapshotRecovery(t *testing.T, ctx context.Context, root string) {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var installationID string
	if err := db.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&installationID); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(root, "offline-snapshot.sqlite")
	_, snapshotErr := sqlitebackup.Snapshot(ctx, db, snapshotPath, sqlitebackup.Options{PagesPerStep: 16})
	closeErr := db.Close()
	if snapshotErr != nil || closeErr != nil {
		t.Fatalf("offline SQLite snapshot failed: %v %v", snapshotErr, closeErr)
	}
	snapshot, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	trust := backup.GenericSetRecovery{Signer: public, InstallationID: installationID, BackupID: uuid.NewString(), SnapshotSHA256: hex.EncodeToString(digest[:])}
	empty := backup.GenericSet{Version: 1, InstallationID: installationID, BackupID: trust.BackupID, SnapshotSHA256: trust.SnapshotSHA256, Objects: []backup.ObjectReceipt{}}
	genericSet, err := backup.SignGenericSet(empty, private)
	if err != nil {
		t.Fatal(err)
	}
	goSet, err := backup.SignGoSet(backup.GoSet(empty), private)
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if _, err := backup.EncryptSnapshot(ctx, bytes.NewReader(snapshot), &encrypted, 64<<20, 65<<20, identity.Recipient()); err != nil {
		t.Fatal("offline snapshot encryption:", err)
	}
	parent := filepath.Join(root, "recovery")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(root, "recovery-stage")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stage := func() (backup.RecoveryStage, error) {
		file, err := os.CreateTemp(stageDir, "owned-")
		if err != nil {
			return nil, err
		}
		return offlineRecoveryStage{File: file}, nil
	}
	prepared, err := backup.PrepareEncryptedSQLiteGoRecovery(ctx, bytes.NewReader(encrypted.Bytes()), 65<<20, 64<<20, 10, 10, genericSet, trust, goSet, trust, parent, "isolated", nil, nil, identity, stage)
	if err != nil || prepared.DatabasePath == "" {
		t.Fatalf("offline isolated SQLite recovery preparation failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "isolated", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal("offline recovery did not retain its incomplete marker:", err)
	}
	if entries, err := os.ReadDir(stageDir); err != nil || len(entries) != 0 {
		t.Fatalf("offline recovery staging cleanup failed: %v", err)
	}
}
