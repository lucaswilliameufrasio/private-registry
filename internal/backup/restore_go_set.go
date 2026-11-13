package backup

import (
	"context"
	"errors"

	"filippo.io/age"
	"private-registry/internal/storage"
)

// RestoreGoSet verifies Go-specific set identity and inventory, then restores
// every object to an isolated destination. Failures can leave partial output;
// the caller must keep it unpromoted and reconcile it. This is not a complete
// installation recovery or evidence that other formats were restored.
func RestoreGoSet(ctx context.Context, set GoSetEnvelope, trusted GenericSetRecovery, sources []RecoveryObjectSource, identity age.Identity, newStage func() (RecoveryStage, error), destination storage.Driver) error {
	if ctx == nil || identity == nil || newStage == nil || destination == nil {
		return errors.New("Go set recovery parameters are invalid")
	}
	verified, err := VerifyGoSetInventory(set, trusted.Signer, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory)
	if err != nil {
		return err
	}
	return restoreVerifiedSet(ctx, GenericSet(verified), trusted, sources, identity, newStage, destination)
}
