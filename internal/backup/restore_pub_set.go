package backup

import (
	"context"
	"errors"

	"filippo.io/age"
	"private-registry/internal/storage"
)

// RestorePubSet validates independent trust and exact inventory before
// restoring to a caller-owned isolated destination. Partial output is never a
// promoted or complete installation recovery.
func RestorePubSet(ctx context.Context, set PubSetEnvelope, trusted GenericSetRecovery, sources []RecoveryObjectSource, identity age.Identity, newStage func() (RecoveryStage, error), destination storage.Driver) error {
	if ctx == nil || identity == nil || newStage == nil || destination == nil {
		return errors.New("Pub set recovery parameters are invalid")
	}
	verified, err := VerifyPubSetInventory(set, trusted.Signer, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory)
	if err != nil {
		return err
	}
	return restoreVerifiedSet(ctx, GenericSet(verified), trusted, sources, identity, newStage, destination)
}
