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
	"sort"
	"testing"

	"filippo.io/age"
	"github.com/google/uuid"
	"private-registry/internal/storage"
)

type testRecoveryStage struct{ *os.File }

func (s testRecoveryStage) Close() error {
	name := s.Name()
	closeErr := s.File.Close()
	removeErr := os.Remove(name)
	if closeErr != nil {
		return closeErr
	}
	return removeErr
}

func TestRestoreGenericSetRequiresCompleteMetadataAndIsolatedDestination(t *testing.T) {
	ctx := context.Background()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	installationID, backupID, workspace := uuid.NewString(), uuid.NewString(), uuid.NewString()
	snapshot := sha256.Sum256([]byte("synthetic snapshot"))
	trusted := GenericSetRecovery{Signer: public, InstallationID: installationID, BackupID: backupID, SnapshotSHA256: hex.EncodeToString(snapshot[:])}
	set := GenericSet{Version: 1, InstallationID: installationID, BackupID: backupID, SnapshotSHA256: trusted.SnapshotSHA256, Objects: []ObjectReceipt{}}
	sources := make([]RecoveryObjectSource, 0, 2)
	for _, text := range []string{"synthetic first", "synthetic second"} {
		payload := []byte(text)
		plainHash := sha256.Sum256(payload)
		key := storage.ObjectKey{WorkspaceID: workspace, SHA256: hex.EncodeToString(plainHash[:])}
		object := GenericObject{Key: key, Size: int64(len(payload))}
		var encrypted bytes.Buffer
		source := syntheticDriver{body: payload, info: storage.ObjectInfo{Key: key, Size: object.Size}}
		if err := EncryptGenericObject(ctx, source, object, &encrypted, identity.Recipient()); err != nil {
			t.Fatal(err)
		}
		ciphertext := bytes.Clone(encrypted.Bytes())
		cipherHash := sha256.Sum256(ciphertext)
		receipt := ObjectReceipt{Version: 1, InstallationID: installationID, BackupID: backupID, WorkspaceID: workspace, PlainSHA256: key.SHA256, PlainBytes: object.Size, CipherSHA256: hex.EncodeToString(cipherHash[:]), CipherBytes: int64(len(ciphertext))}
		envelope, err := SignObjectReceipt(receipt, private)
		if err != nil {
			t.Fatal(err)
		}
		trusted.Inventory = append(trusted.Inventory, object)
		set.Objects = append(set.Objects, receipt)
		sources = append(sources, RecoveryObjectSource{Receipt: envelope, Open: func(context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(ciphertext)), nil }})
	}
	sort.Slice(set.Objects, func(i, j int) bool { return set.Objects[i].PlainSHA256 < set.Objects[j].PlainSHA256 })
	setEnvelope, err := SignGenericSet(set, private)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	protected, err := storage.NewFileSystem(filepath.Join(root, "protected"))
	if err != nil {
		t.Fatal(err)
	}
	protectedBytes := []byte("synthetic protected object outside recovery destination")
	protectedInfo, err := protected.Put(ctx, workspace, bytes.NewReader(protectedBytes), int64(len(protectedBytes)))
	if err != nil {
		t.Fatal(err)
	}
	destination, err := storage.NewFileSystem(filepath.Join(root, "restored"))
	if err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(root, "staging")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stage := func() (RecoveryStage, error) {
		file, err := os.CreateTemp(stageDir, "owned-*")
		if err != nil {
			return nil, err
		}
		return testRecoveryStage{File: file}, nil
	}
	if err := RestoreGenericSet(ctx, setEnvelope, trusted, sources[:1], identity, stage, destination); err == nil {
		t.Fatal("incomplete set was accepted")
	}
	if reader, _, err := destination.Open(ctx, trusted.Inventory[0].Key); err == nil {
		_ = reader.Close()
		t.Fatal("incomplete metadata wrote to destination")
	}
	if err := RestoreGenericSet(ctx, setEnvelope, trusted, []RecoveryObjectSource{sources[0], sources[0]}, identity, stage, destination); err == nil {
		t.Fatal("duplicate source was accepted")
	}
	partial, err := storage.NewFileSystem(filepath.Join(root, "partial"))
	if err != nil {
		t.Fatal(err)
	}
	badSources := append([]RecoveryObjectSource(nil), sources...)
	badSources[1].Open = func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte("truncated synthetic ciphertext"))), nil
	}
	if err := RestoreGenericSet(ctx, setEnvelope, trusted, badSources, identity, stage, partial); err == nil {
		t.Fatal("corrupt second ciphertext was accepted")
	}
	protectedReader, afterInfo, err := protected.Open(ctx, protectedInfo.Key)
	if err != nil {
		t.Fatal("protected object unavailable after failed isolated restore:", err)
	}
	afterBytes, readErr := io.ReadAll(protectedReader)
	closeErr := protectedReader.Close()
	if readErr != nil || closeErr != nil || afterInfo != protectedInfo || !bytes.Equal(afterBytes, protectedBytes) {
		t.Fatal("failed isolated restore changed the protected object")
	}
	firstReader, _, err := partial.Open(ctx, trusted.Inventory[0].Key)
	if err != nil {
		t.Fatal("expected first object in unpromotable partial destination:", err)
	}
	if err := firstReader.Close(); err != nil {
		t.Fatal(err)
	}
	if reader, _, err := partial.Open(ctx, trusted.Inventory[1].Key); err == nil {
		_ = reader.Close()
		t.Fatal("corrupt second object was written")
	}
	if err := RestoreGenericSet(ctx, setEnvelope, trusted, sources, identity, stage, destination); err != nil {
		t.Fatal("restore complete synthetic set:", err)
	}
	protectedReader, afterInfo, err = protected.Open(ctx, protectedInfo.Key)
	if err != nil {
		t.Fatal("protected object unavailable after successful isolated restore:", err)
	}
	afterBytes, readErr = io.ReadAll(protectedReader)
	closeErr = protectedReader.Close()
	if readErr != nil || closeErr != nil || afterInfo != protectedInfo || !bytes.Equal(afterBytes, protectedBytes) {
		t.Fatal("successful isolated restore changed the protected object")
	}
	for _, object := range trusted.Inventory {
		reader, info, err := destination.Open(ctx, object.Key)
		if err != nil {
			t.Fatal(err)
		}
		if err := reader.Close(); err != nil || info.Size != object.Size {
			t.Fatalf("restored object verification: %v", err)
		}
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("owned staging was not removed: entries=%d error=%v", len(entries), err)
	}
}
