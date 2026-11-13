package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"private-registry/internal/storage"
)

func TestCaptureAndRestoreGoSetUsesSeparateSignatureDomain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	newStore := func(name string) *storage.FileSystem {
		t.Helper()
		store, err := storage.NewFileSystem(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	source, remote, restored := newStore("source"), newStore("remote"), newStore("restored")
	data := []byte("synthetic Go module ZIP")
	workspace := uuid.NewString()
	object, err := source.Put(ctx, workspace, bytes.NewReader(data), int64(len(data)))
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
	digest := sha256.Sum256([]byte("synthetic stable snapshot"))
	trusted := GenericSetRecovery{Signer: public, InstallationID: uuid.NewString(), BackupID: uuid.NewString(), SnapshotSHA256: hex.EncodeToString(digest[:]), Inventory: []GenericObject{{Key: object.Key, Size: object.Size}}}
	stageDir := filepath.Join(root, "stage")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	newStage := func() (RecoveryStage, error) {
		file, err := os.CreateTemp(stageDir, "owned-*")
		if err != nil {
			return nil, err
		}
		return testRecoveryStage{File: file}, nil
	}
	captured, err := CaptureGoSet(ctx, trusted, source, remote, identity.Recipient(), private, 4096, newStage)
	if err != nil || len(captured.Receipts) != 1 {
		t.Fatalf("capture Go set receipts=%d err=%v", len(captured.Receipts), err)
	}
	verified, err := VerifyGoSetInventory(captured.Set, public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGenericSet(GenericSetEnvelope(captured.Set), public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256); err == nil {
		t.Fatal("Go set accepted as a generic set")
	}
	if _, err := VerifyGoSetInventory(captured.Set, public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, nil); err == nil {
		t.Fatal("Go set with omitted inventory accepted")
	}
	genericEnvelope, err := SignGenericSet(GenericSet(verified), private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGoSetInventory(GoSetEnvelope(genericEnvelope), public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory); err == nil {
		t.Fatal("generic set accepted as a Go set")
	}
	tampered := captured.Set
	tampered.Payload = bytes.Clone(tampered.Payload)
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	if _, err := VerifyGoSetInventory(tampered, public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory); err == nil {
		t.Fatal("tampered Go set was accepted")
	}
	if _, err := VerifyGoSetInventory(captured.Set, public, trusted.InstallationID, uuid.NewString(), trusted.SnapshotSHA256, trusted.Inventory); err == nil {
		t.Fatal("Go set from another backup was accepted")
	}
	receipt, err := VerifyObjectReceipt(captured.Receipts[0], public, trusted.InstallationID, trusted.BackupID)
	if err != nil {
		t.Fatal(err)
	}
	key := storage.ObjectKey{WorkspaceID: workspace, SHA256: receipt.CipherSHA256}
	sources := []RecoveryObjectSource{{Receipt: captured.Receipts[0], Open: func(ctx context.Context) (io.ReadCloser, error) {
		reader, _, err := remote.Open(ctx, key)
		return reader, err
	}}}
	if err := RestoreGoSet(ctx, captured.Set, trusted, sources, identity, newStage, restored); err != nil {
		t.Fatal("restore Go set:", err)
	}
	var recovered bytes.Buffer
	if err := CopyGenericObject(ctx, restored, trusted.Inventory[0], &recovered); err != nil || !bytes.Equal(recovered.Bytes(), data) {
		t.Fatalf("restored Go object differs: %v", err)
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging remains entries=%d err=%v", len(entries), err)
	}
}
