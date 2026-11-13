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

type corruptCaptureReadback struct{ storage.Driver }

func (s corruptCaptureReadback) Open(ctx context.Context, key storage.ObjectKey) (io.ReadCloser, storage.ObjectInfo, error) {
	reader, info, err := s.Driver.Open(ctx, key)
	if err != nil {
		return nil, storage.ObjectInfo{}, err
	}
	if err := reader.Close(); err != nil {
		return nil, storage.ObjectInfo{}, err
	}
	return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'x'}, int(info.Size)))), info, nil
}

func TestCaptureAndRecoverGenericSet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	root := t.TempDir()
	openStore := func(name string) *storage.FileSystem {
		t.Helper()
		store, err := storage.NewFileSystem(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	source, remote, restored := openStore("source"), openStore("remote"), openStore("restored")
	workspace := uuid.NewString()
	var inventory []GenericObject
	for _, data := range [][]byte{[]byte("synthetic first"), []byte("synthetic second")} {
		info, err := source.Put(ctx, workspace, bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		inventory = append(inventory, GenericObject{Key: info.Key, Size: info.Size})
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := sha256.Sum256([]byte("synthetic snapshot"))
	trusted := GenericSetRecovery{Signer: public, InstallationID: uuid.NewString(), BackupID: uuid.NewString(), SnapshotSHA256: hex.EncodeToString(snapshot[:]), Inventory: inventory}
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
	if result, err := CaptureGenericSet(ctx, trusted, source, remote, identity.Recipient(), private, 1, newStage); err == nil || len(result.Receipts) != 0 || len(result.Set.Payload) != 0 {
		t.Fatal("capture beyond ciphertext limit returned a signed set")
	}
	corruptRemote := corruptCaptureReadback{Driver: openStore("corrupt-remote")}
	if result, err := CaptureGenericSet(ctx, trusted, source, corruptRemote, identity.Recipient(), private, 4096, newStage); err == nil || len(result.Receipts) != 0 || len(result.Set.Payload) != 0 {
		t.Fatal("corrupt destination readback returned a signed set")
	}
	if result, err := CaptureGenericSet(context.Background(), trusted, source, remote, identity.Recipient(), private, 4096, newStage); err == nil || len(result.Set.Payload) != 0 {
		t.Fatal("capture without deadline returned a signed set")
	}
	if _, err := CaptureGenericSet(ctx, trusted, source, remote, identity.Recipient(), private, 2<<30, newStage); err != nil {
		t.Fatalf("capture with supported ciphertext limit: %v", err)
	}
	if result, err := CaptureGenericSet(ctx, trusted, source, remote, identity.Recipient(), private, (2<<30)+1, newStage); err == nil || len(result.Set.Payload) != 0 {
		t.Fatal("capture above ciphertext limit returned a signed set")
	}
	result, err := CaptureGenericSet(ctx, trusted, source, remote, identity.Recipient(), private, 4096, newStage)
	if err != nil || len(result.Receipts) != len(inventory) {
		t.Fatalf("capture generic set receipts=%d err=%v", len(result.Receipts), err)
	}
	if _, err := VerifyGenericSetInventory(result.Set, public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, inventory); err != nil {
		t.Fatal("verify captured set:", err)
	}
	sources := make([]RecoveryObjectSource, 0, len(result.Receipts))
	for _, envelope := range result.Receipts {
		receipt, err := VerifyObjectReceipt(envelope, public, trusted.InstallationID, trusted.BackupID)
		if err != nil {
			t.Fatal(err)
		}
		cipherKey := storage.ObjectKey{WorkspaceID: receipt.WorkspaceID, SHA256: receipt.CipherSHA256}
		sources = append(sources, RecoveryObjectSource{Receipt: envelope, Open: func(ctx context.Context) (io.ReadCloser, error) {
			reader, _, err := remote.Open(ctx, cipherKey)
			return reader, err
		}})
	}
	if err := RestoreGenericSet(ctx, result.Set, trusted, sources, identity, newStage, restored); err != nil {
		t.Fatal("recover captured synthetic set:", err)
	}
	for _, object := range inventory {
		var before, after bytes.Buffer
		if err := CopyGenericObject(ctx, source, object, &before); err != nil {
			t.Fatal(err)
		}
		if err := CopyGenericObject(ctx, restored, object, &after); err != nil || !bytes.Equal(before.Bytes(), after.Bytes()) {
			t.Fatalf("restored object differs from source: %v", err)
		}
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging remains entries=%d error=%v", len(entries), err)
	}
}
