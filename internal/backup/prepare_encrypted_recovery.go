package backup

import (
	"context"
	"errors"
	"io"

	"filippo.io/age"
)

// PrepareEncryptedSQLiteGenericRecovery verifies the signed generic context,
// decrypts the snapshot into private staging, and prepares its SQLite catalog
// and generic objects in a new isolated directory. The marker remains in
// place: this is not a complete installation recovery or authorization to
// serve. The caller must provide trust independently, enforce hard resource
// limits and ensure exclusive, private staging which is removed on Close.
// Failures after destination creation can leave an incomplete directory.
func PrepareEncryptedSQLiteGenericRecovery(ctx context.Context, ciphertext io.Reader, maxCiphertext, maxSnapshotBytes int64, maxObjects, maxReferences int, set GenericSetEnvelope, trusted GenericSetRecovery, parent, name string, sources []RecoveryObjectSource, identity age.Identity, newStage func() (RecoveryStage, error)) (result PreparedSQLiteRecovery, retErr error) {
	if ctx == nil || ciphertext == nil || identity == nil || newStage == nil {
		return result, errors.New("encrypted SQLite recovery parameters are invalid")
	}
	if _, err := VerifyGenericSet(set, trusted.Signer, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256); err != nil {
		return result, err
	}
	stage, err := newStage()
	if err != nil || stage == nil {
		if stage != nil {
			_ = stage.Close()
		}
		return result, errors.New("encrypted SQLite recovery staging could not be created")
	}
	defer func() {
		if err := stage.Close(); err != nil {
			result = PreparedSQLiteRecovery{}
			retErr = errors.Join(retErr, errors.New("encrypted SQLite recovery staging could not be removed"))
		}
	}()
	end, err := stage.Seek(0, io.SeekEnd)
	if err != nil || end != 0 {
		return result, errors.New("encrypted SQLite recovery staging must be empty")
	}
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		return result, errors.New("encrypted SQLite recovery staging cannot be rewound")
	}
	if _, err := DecryptSnapshot(ctx, ciphertext, stage, maxCiphertext, maxSnapshotBytes, trusted.SnapshotSHA256, identity); err != nil {
		return result, err
	}
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		return result, errors.New("encrypted SQLite recovery staging cannot be rewound")
	}
	return PrepareSQLiteGenericRecovery(ctx, stage, maxSnapshotBytes, maxObjects, maxReferences, set, trusted, parent, name, sources, identity, newStage)
}
