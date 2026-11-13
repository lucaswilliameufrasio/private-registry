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

func TestVerifyGenericReceiptsMatchesExactInventory(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	installationID, backupID, workspace := uuid.NewString(), uuid.NewString(), uuid.NewString()
	makeReceipt := func(body string) (GenericObject, ObjectReceiptEnvelope) {
		t.Helper()
		digest := sha256.Sum256([]byte(body))
		key := storage.ObjectKey{WorkspaceID: workspace, SHA256: hex.EncodeToString(digest[:])}
		object := GenericObject{Key: key, Size: int64(len(body))}
		receipt := ObjectReceipt{Version: 1, InstallationID: installationID, BackupID: backupID, WorkspaceID: workspace, PlainSHA256: key.SHA256, PlainBytes: object.Size, CipherSHA256: key.SHA256, CipherBytes: 1}
		envelope, err := SignObjectReceipt(receipt, private)
		if err != nil {
			t.Fatal(err)
		}
		return object, envelope
	}
	first, firstReceipt := makeReceipt("first")
	second, secondReceipt := makeReceipt("second")
	inventory := []GenericObject{first, second}
	receipts := []ObjectReceiptEnvelope{secondReceipt, firstReceipt}
	verified, err := VerifyGenericReceipts(inventory, receipts, public, installationID, backupID, 2)
	if err != nil || len(verified) != 2 {
		t.Fatalf("matching inventory verification count=%d error=%v", len(verified), err)
	}
	for _, tc := range []struct {
		name      string
		inventory []GenericObject
		receipts  []ObjectReceiptEnvelope
	}{
		{name: "missing", inventory: inventory, receipts: receipts[:1]},
		{name: "extra", inventory: inventory[:1], receipts: receipts},
		{name: "duplicate receipt", inventory: inventory, receipts: []ObjectReceiptEnvelope{firstReceipt, firstReceipt}},
		{name: "duplicate inventory", inventory: []GenericObject{first, first}, receipts: receipts},
		{name: "size mismatch", inventory: []GenericObject{{Key: first.Key, Size: first.Size + 1}, second}, receipts: receipts},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyGenericReceipts(tc.inventory, tc.receipts, public, installationID, backupID, 2); err == nil {
				t.Fatal("inconsistent inventory accepted")
			}
		})
	}
	if _, err := VerifyGenericReceipts(inventory, receipts, public, installationID, uuid.NewString(), 2); err == nil {
		t.Fatal("wrong backup context accepted")
	}
	if _, err := VerifyGenericReceipts(nil, nil, nil, installationID, backupID, 2); err == nil {
		t.Fatal("missing trust accepted for empty inventory")
	}
}
