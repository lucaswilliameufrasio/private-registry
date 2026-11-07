package backup

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"private-registry/internal/storage"
)

func TestGenericSetAuthenticatesEmptyAndNonemptyInventories(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("synthetic snapshot"))
	set := GenericSet{Version: 1, InstallationID: uuid.NewString(), BackupID: uuid.NewString(), SnapshotSHA256: hex.EncodeToString(digest[:]), Objects: []ObjectReceipt{}}
	empty, err := SignGenericSet(set, private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyGenericSet(empty, public, set.InstallationID, set.BackupID, set.SnapshotSHA256)
	if err != nil || len(verified.Objects) != 0 || verified.Objects == nil {
		t.Fatalf("verify signed empty set: %v", err)
	}
	if _, err := VerifyGenericSet(empty, other, set.InstallationID, set.BackupID, set.SnapshotSHA256); err == nil {
		t.Fatal("untrusted signer accepted")
	}
	if _, err := VerifyGenericSet(empty, public, set.InstallationID, uuid.NewString(), set.SnapshotSHA256); err == nil {
		t.Fatal("wrong backup accepted")
	}
	if _, err := VerifyGenericSet(empty, public, set.InstallationID, set.BackupID, hex.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("wrong snapshot accepted")
	}
	object := ObjectReceipt{Version: 1, InstallationID: set.InstallationID, BackupID: set.BackupID, WorkspaceID: uuid.NewString(), PlainSHA256: hex.EncodeToString(digest[:]), PlainBytes: 1, CipherSHA256: hex.EncodeToString(digest[:]), CipherBytes: 1}
	set.Objects = []ObjectReceipt{object}
	envelope, err := SignGenericSet(set, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGenericSet(envelope, public, set.InstallationID, set.BackupID, set.SnapshotSHA256); err != nil {
		t.Fatalf("verify nonempty set: %v", err)
	}
	inventory := []GenericObject{{Key: storage.ObjectKey{WorkspaceID: object.WorkspaceID, SHA256: object.PlainSHA256}, Size: object.PlainBytes}}
	if _, err := VerifyGenericSetInventory(envelope, public, set.InstallationID, set.BackupID, set.SnapshotSHA256, inventory); err != nil {
		t.Fatalf("verify matching snapshot inventory: %v", err)
	}
	if _, err := VerifyGenericSetInventory(envelope, public, set.InstallationID, set.BackupID, set.SnapshotSHA256, nil); err == nil {
		t.Fatal("missing object from snapshot inventory accepted")
	}
	inventory[0].Size++
	if _, err := VerifyGenericSetInventory(envelope, public, set.InstallationID, set.BackupID, set.SnapshotSHA256, inventory); err == nil {
		t.Fatal("different snapshot object size accepted")
	}
	set.Objects = []ObjectReceipt{object, object}
	if _, err := SignGenericSet(set, private); err == nil {
		t.Fatal("duplicate object accepted")
	}
	set.Objects = nil
	if _, err := SignGenericSet(set, private); err == nil {
		t.Fatal("ambiguous null object list accepted")
	}
	modified := GenericSetEnvelope{Payload: append([]byte(nil), envelope.Payload...), Signature: envelope.Signature}
	modified.Payload[10] ^= 1
	if _, err := VerifyGenericSet(modified, public, set.InstallationID, set.BackupID, set.SnapshotSHA256); err == nil {
		t.Fatal("altered set accepted")
	}
}
