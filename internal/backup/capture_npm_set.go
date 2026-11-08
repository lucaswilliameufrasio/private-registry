package backup

import (
	"context"
	"crypto/ed25519"

	"filippo.io/age"
	"private-registry/internal/storage"
)

type CapturedNPMSet struct {
	Set      NPMSetEnvelope
	Receipts []ObjectReceiptEnvelope
}

// CaptureNPMSet requires inventory derived from an authenticated snapshot
// and independent protection against GC. Failed capture may leave remote
// orphans. This set does not publish a complete backup.
func CaptureNPMSet(ctx context.Context, trusted GenericSetRecovery, source, destination storage.Driver, recipient age.Recipient, signer ed25519.PrivateKey, maxCiphertext int64, newStage func() (RecoveryStage, error)) (CapturedNPMSet, error) {
	captured, err := CaptureGenericSet(ctx, trusted, source, destination, recipient, signer, maxCiphertext, newStage)
	if err != nil {
		return CapturedNPMSet{}, err
	}
	set, err := VerifyGenericSetInventory(captured.Set, trusted.Signer, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory)
	if err != nil {
		return CapturedNPMSet{}, err
	}
	signed, err := SignNPMSet(NPMSet(set), signer)
	if err != nil {
		return CapturedNPMSet{}, err
	}
	return CapturedNPMSet{Set: signed, Receipts: captured.Receipts}, nil
}
