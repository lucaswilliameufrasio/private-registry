package backup

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"

	"filippo.io/age"
	"private-registry/internal/storage"
)

// GenericSetRecovery contains independently trusted recovery context. Snapshot
// integrity and inventory must be verified before constructing this value.
type GenericSetRecovery struct {
	Signer         ed25519.PublicKey
	InstallationID string
	BackupID       string
	SnapshotSHA256 string
	Inventory      []GenericObject
}

// RestoreGenericSetObject requires the exact independently signed object receipt
// to appear in the authenticated generic set matching the recovered snapshot.
// It does not establish freshness, restore other objects or promote a backup.
func RestoreGenericSetObject(ctx context.Context, ciphertext io.Reader, setEnvelope GenericSetEnvelope, objectEnvelope ObjectReceiptEnvelope, trusted GenericSetRecovery, identity age.Identity, cipherStage, plainStage io.ReadWriteSeeker, destination storage.Driver) error {
	set, err := VerifyGenericSetInventory(setEnvelope, trusted.Signer, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory)
	if err != nil {
		return err
	}
	receipt, err := VerifyObjectReceipt(objectEnvelope, trusted.Signer, trusted.InstallationID, trusted.BackupID)
	if err != nil {
		return err
	}
	found := false
	for _, object := range set.Objects {
		if object == receipt {
			found = true
			break
		}
	}
	if !found {
		return errors.New("generic object receipt is not in the authenticated backup set")
	}
	return RestoreReceiptedGenericObject(ctx, ciphertext, objectEnvelope, trusted.Signer, trusted.InstallationID, trusted.BackupID, identity, cipherStage, plainStage, destination)
}
