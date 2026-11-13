package backup

import (
	"context"
	"crypto/ed25519"

	"filippo.io/age"
	"private-registry/internal/storage"
)

type CapturedPubSet struct {
	Set      PubSetEnvelope
	Receipts []ObjectReceiptEnvelope
}

// CapturePubSet requires inventory derived from an authenticated snapshot
// and independent protection against GC. Failed capture may leave remote
// orphans. This set does not publish a complete backup.
func CapturePubSet(ctx context.Context, trusted GenericSetRecovery, source, destination storage.Driver, recipient age.Recipient, signer ed25519.PrivateKey, maxCiphertext int64, newStage func() (RecoveryStage, error)) (CapturedPubSet, error) {
	captured, err := CaptureGenericSet(ctx, trusted, source, destination, recipient, signer, maxCiphertext, newStage)
	if err != nil {
		return CapturedPubSet{}, err
	}
	set, err := VerifyGenericSetInventory(captured.Set, trusted.Signer, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory)
	if err != nil {
		return CapturedPubSet{}, err
	}
	signed, err := SignPubSet(PubSet(set), signer)
	if err != nil {
		return CapturedPubSet{}, err
	}
	return CapturedPubSet{Set: signed, Receipts: captured.Receipts}, nil
}
