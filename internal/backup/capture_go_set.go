package backup

import (
	"context"
	"crypto/ed25519"

	"filippo.io/age"
	"private-registry/internal/storage"
)

type CapturedGoSet struct {
	Set      GoSetEnvelope
	Receipts []ObjectReceiptEnvelope
}

// CaptureGoSet encrypts and verifies Go ZIP objects, then signs their set in a
// Go-specific domain. The caller must derive inventory from the trusted snapshot
// and protect objects from GC throughout capture. Partial failures may leave
// remote orphans; success is not a complete backup or publication marker.
func CaptureGoSet(ctx context.Context, trusted GenericSetRecovery, source, destination storage.Driver, recipient age.Recipient, signer ed25519.PrivateKey, maxCiphertext int64, newStage func() (RecoveryStage, error)) (CapturedGoSet, error) {
	captured, err := CaptureGenericSet(ctx, trusted, source, destination, recipient, signer, maxCiphertext, newStage)
	if err != nil {
		return CapturedGoSet{}, err
	}
	set, err := VerifyGenericSetInventory(captured.Set, trusted.Signer, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory)
	if err != nil {
		return CapturedGoSet{}, err
	}
	signed, err := SignGoSet(GoSet(set), signer)
	if err != nil {
		return CapturedGoSet{}, err
	}
	return CapturedGoSet{Set: signed, Receipts: captured.Receipts}, nil
}
