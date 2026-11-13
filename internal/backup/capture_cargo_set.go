package backup

import (
	"context"
	"crypto/ed25519"

	"filippo.io/age"
	"private-registry/internal/storage"
)

type CapturedCargoSet struct {
	Set      CargoSetEnvelope
	Receipts []ObjectReceiptEnvelope
}

// CaptureCargoSet requires inventory derived from an authenticated snapshot
// and independent protection against GC. Failed capture may leave remote
// orphans. This set does not publish a complete backup.
func CaptureCargoSet(ctx context.Context, trusted GenericSetRecovery, source, destination storage.Driver, recipient age.Recipient, signer ed25519.PrivateKey, maxCiphertext int64, newStage func() (RecoveryStage, error)) (CapturedCargoSet, error) {
	captured, err := CaptureGenericSet(ctx, trusted, source, destination, recipient, signer, maxCiphertext, newStage)
	if err != nil {
		return CapturedCargoSet{}, err
	}
	set, err := VerifyGenericSetInventory(captured.Set, trusted.Signer, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory)
	if err != nil {
		return CapturedCargoSet{}, err
	}
	signed, err := SignCargoSet(CargoSet(set), signer)
	if err != nil {
		return CapturedCargoSet{}, err
	}
	return CapturedCargoSet{Set: signed, Receipts: captured.Receipts}, nil
}
