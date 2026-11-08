package backup

import (
	"context"
	"errors"
	"io"

	"filippo.io/age"
	"private-registry/internal/storage"
)

// RecoveryObjectSource opens the ciphertext described by Receipt. The caller
// is responsible for an isolated source, network policy and bounded I/O.
type RecoveryObjectSource struct {
	Receipt ObjectReceiptEnvelope
	Open    func(context.Context) (io.ReadCloser, error)
}

type RecoveryStage interface {
	io.ReadWriteSeeker
	io.Closer
}

// RestoreGenericSet restores every generic object to a caller-owned isolated
// destination. All signed metadata is checked before any writes. A later I/O
// failure can leave an incomplete destination; callers must never promote it
// and must dispose of or reconcile only their own isolated recovery resources.
// newStage must create a new empty private file and remove it on Close.
// This does not recover a database, keys, non-generic formats or credentials.
func RestoreGenericSet(ctx context.Context, setEnvelope GenericSetEnvelope, trusted GenericSetRecovery, sources []RecoveryObjectSource, identity age.Identity, newStage func() (RecoveryStage, error), destination storage.Driver) error {
	if ctx == nil || identity == nil || newStage == nil || destination == nil {
		return errors.New("generic set recovery parameters are invalid")
	}
	set, err := VerifyGenericSetInventory(setEnvelope, trusted.Signer, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256, trusted.Inventory)
	if err != nil {
		return err
	}
	return restoreVerifiedSet(ctx, set, trusted, sources, identity, newStage, destination)
}

func restoreVerifiedSet(ctx context.Context, set GenericSet, trusted GenericSetRecovery, sources []RecoveryObjectSource, identity age.Identity, newStage func() (RecoveryStage, error), destination storage.Driver) error {
	if len(sources) != len(set.Objects) {
		return errors.New("generic recovery sources do not match the signed set")
	}
	expected := make(map[storage.ObjectKey]ObjectReceipt, len(set.Objects))
	for _, object := range set.Objects {
		expected[storage.ObjectKey{WorkspaceID: object.WorkspaceID, SHA256: object.PlainSHA256}] = object
	}
	for _, source := range sources {
		if source.Open == nil {
			return errors.New("generic recovery source is unavailable")
		}
		receipt, err := VerifyObjectReceipt(source.Receipt, trusted.Signer, trusted.InstallationID, trusted.BackupID)
		if err != nil {
			return err
		}
		key := storage.ObjectKey{WorkspaceID: receipt.WorkspaceID, SHA256: receipt.PlainSHA256}
		if expectedReceipt, exists := expected[key]; !exists || expectedReceipt != receipt {
			return errors.New("generic recovery source does not match the signed set")
		}
		delete(expected, key)
	}
	if len(expected) != 0 {
		return errors.New("generic recovery sources do not match the signed set")
	}
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := restoreOneGenericSource(ctx, source, trusted, identity, newStage, destination); err != nil {
			return err
		}
	}
	return nil
}

func restoreOneGenericSource(ctx context.Context, source RecoveryObjectSource, trusted GenericSetRecovery, identity age.Identity, newStage func() (RecoveryStage, error), destination storage.Driver) (retErr error) {
	reader, err := source.Open(ctx)
	if err != nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		return errors.New("generic recovery ciphertext could not be opened")
	}
	defer func() {
		if err := reader.Close(); err != nil {
			retErr = errors.Join(retErr, errors.New("generic recovery ciphertext could not be closed"))
		}
	}()
	cipherStage, err := newStage()
	if err != nil || cipherStage == nil {
		if cipherStage != nil {
			_ = cipherStage.Close()
		}
		return errors.New("generic recovery ciphertext staging could not be created")
	}
	defer func() {
		if err := cipherStage.Close(); err != nil {
			retErr = errors.Join(retErr, errors.New("generic recovery ciphertext staging could not be removed"))
		}
	}()
	plainStage, err := newStage()
	if err != nil || plainStage == nil {
		if plainStage != nil {
			_ = plainStage.Close()
		}
		return errors.New("generic recovery plaintext staging could not be created")
	}
	defer func() {
		if err := plainStage.Close(); err != nil {
			retErr = errors.Join(retErr, errors.New("generic recovery plaintext staging could not be removed"))
		}
	}()
	return RestoreReceiptedGenericObject(ctx, reader, source.Receipt, trusted.Signer, trusted.InstallationID, trusted.BackupID, identity, cipherStage, plainStage, destination)
}
