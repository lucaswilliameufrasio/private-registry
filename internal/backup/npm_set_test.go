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
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/uuid"
	"private-registry/internal/storage"
)

func TestCaptureRestoreNPMSetUsesIndependentDomain(t *testing.T) {
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
	data := []byte("synthetic NPM archive")
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
	captured, err := CaptureNPMSet(ctx, trusted, source, remote, identity.Recipient(), private, 4096, newStage)
	if err != nil || len(captured.Receipts) != 1 {
		t.Fatalf("capture NPM set receipts=%d err=%v", len(captured.Receipts), err)
	}
	verified, err := VerifyNPMSetInventory(captured.Set, public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGenericSet(GenericSetEnvelope(captured.Set), public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256); err == nil {
		t.Fatal("NPM set accepted as generic set")
	}
	if _, err := VerifyGoSet(GoSetEnvelope(captured.Set), public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256); err == nil {
		t.Fatal("NPM set accepted as Go set")
	}
	if _, err := VerifyCargoSet(CargoSetEnvelope(captured.Set), public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256); err == nil {
		t.Fatal("npm set accepted as Cargo set")
	}
	goEnvelope, err := SignGoSet(GoSet(verified), private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyNPMSetInventory(NPMSetEnvelope(goEnvelope), public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory); err == nil {
		t.Fatal("Go set accepted as NPM set")
	}
	if _, err := VerifyNPMSetInventory(captured.Set, public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, nil); err == nil {
		t.Fatal("NPM set accepted without inventory")
	}
	tampered := captured.Set
	tampered.Payload = bytes.Clone(tampered.Payload)
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	if _, err := VerifyNPMSetInventory(tampered, public, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory); err == nil {
		t.Fatal("tampered NPM set was accepted")
	}
	if _, err := VerifyNPMSetInventory(captured.Set, public, trusted.InstallationID, uuid.NewString(), trusted.SnapshotSHA256, trusted.Inventory); err == nil {
		t.Fatal("NPM set from another backup was accepted")
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
	var opens atomic.Int64
	observedSources := []RecoveryObjectSource{{Receipt: captured.Receipts[0], Open: func(ctx context.Context) (io.ReadCloser, error) {
		opens.Add(1)
		return sources[0].Open(ctx)
	}}}
	wrongTrust := trusted
	wrongTrust.BackupID = uuid.NewString()
	if err := RestoreNPMSet(ctx, captured.Set, wrongTrust, observedSources, identity, newStage, restored); err == nil || opens.Load() != 0 {
		t.Fatal("NPM restore accessed ciphertext before validating backup context")
	}
	badSignature := captured.Set
	badSignature.Signature = bytes.Clone(badSignature.Signature)
	badSignature.Signature[0] ^= 1
	if err := RestoreNPMSet(ctx, badSignature, trusted, observedSources, identity, newStage, restored); err == nil || opens.Load() != 0 {
		t.Fatal("npm restore accessed ciphertext before validating set signature")
	}
	if err := RestoreNPMSet(ctx, tampered, trusted, observedSources, identity, newStage, restored); err == nil || opens.Load() != 0 {
		t.Fatal("npm restore accessed ciphertext before validating set payload")
	}
	otherSigner, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner := trusted
	wrongSigner.Signer = otherSigner
	if err := RestoreNPMSet(ctx, captured.Set, wrongSigner, observedSources, identity, newStage, restored); err == nil || opens.Load() != 0 {
		t.Fatal("npm restore accessed ciphertext with an untrusted signer")
	}
	protected := newStore("protected")
	protectedInfo, err := protected.Put(ctx, workspace, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreNPMSet(ctx, captured.Set, trusted, nil, identity, newStage, restored); err == nil {
		t.Fatal("NPM restore accepted missing ciphertext")
	}
	wrongIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreNPMSet(ctx, captured.Set, trusted, sources, wrongIdentity, newStage, restored); err == nil {
		t.Fatal("NPM restore accepted the wrong decryption identity")
	}
	var protectedBytes bytes.Buffer
	if err := CopyGenericObject(ctx, protected, GenericObject{Key: protectedInfo.Key, Size: protectedInfo.Size}, &protectedBytes); err != nil || !bytes.Equal(protectedBytes.Bytes(), data) {
		t.Fatalf("failed NPM restore changed independent storage: %v", err)
	}
	if err := RestoreNPMSet(ctx, captured.Set, trusted, sources, identity, newStage, restored); err != nil {
		t.Fatal("restore NPM set:", err)
	}
	var recovered bytes.Buffer
	if err := CopyGenericObject(ctx, restored, trusted.Inventory[0], &recovered); err != nil || !bytes.Equal(recovered.Bytes(), data) {
		t.Fatalf("restored NPM object differs: %v", err)
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging remains entries=%d err=%v", len(entries), err)
	}
}
