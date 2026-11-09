package backup

import (
	"context"
	"errors"
	"io"
	"path/filepath"

	"filippo.io/age"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/storage"
)

// PrepareEncryptedSQLiteGoRecovery prepares an isolated SQLite catalog plus
// its generic and Go objects from separately signed sets. It never removes the
// incomplete marker or promotes the installation. The caller supplies trust,
// bounded private staging, hard resource limits and isolated source access.
// Configuration, internal keys and all other formats remain outside this flow.
func PrepareEncryptedSQLiteGoRecovery(ctx context.Context, ciphertext io.Reader, maxCiphertext, maxSnapshotBytes int64, maxObjects, maxReferences int, genericSet GenericSetEnvelope, genericTrust GenericSetRecovery, goSet GoSetEnvelope, goTrust GenericSetRecovery, parent, name string, genericSources, goSources []RecoveryObjectSource, identity age.Identity, newStage func() (RecoveryStage, error)) (result PreparedSQLiteRecovery, retErr error) {
	return prepareEncryptedSQLiteFormatsRecovery(ctx, ciphertext, maxCiphertext, maxSnapshotBytes, maxObjects, maxReferences, genericSet, genericTrust, goSet, goTrust, nil, nil, nil, nil, nil, nil, parent, name, genericSources, goSources, nil, nil, nil, identity, newStage)
}

// PrepareEncryptedSQLiteCargoRecovery restores generic, Go and Cargo objects
// into a new isolated directory. The incomplete marker is never removed.
// It does not restore configuration or other formats, nor authorize promotion.
func PrepareEncryptedSQLiteCargoRecovery(ctx context.Context, ciphertext io.Reader, maxCiphertext, maxSnapshotBytes int64, maxObjects, maxReferences int, genericSet GenericSetEnvelope, genericTrust GenericSetRecovery, goSet GoSetEnvelope, goTrust GenericSetRecovery, cargoSet CargoSetEnvelope, cargoTrust GenericSetRecovery, parent, name string, genericSources, goSources, cargoSources []RecoveryObjectSource, identity age.Identity, newStage func() (RecoveryStage, error)) (PreparedSQLiteRecovery, error) {
	return prepareEncryptedSQLiteFormatsRecovery(ctx, ciphertext, maxCiphertext, maxSnapshotBytes, maxObjects, maxReferences, genericSet, genericTrust, goSet, goTrust, &cargoSet, &cargoTrust, nil, nil, nil, nil, parent, name, genericSources, goSources, cargoSources, nil, nil, identity, newStage)
}

// PrepareEncryptedSQLiteNPMRecovery restores generic, Go, Cargo and npm
// objects into a new isolated directory. It never removes the incomplete
// marker, restores configuration or keys, or authorizes promotion.
func PrepareEncryptedSQLiteNPMRecovery(ctx context.Context, ciphertext io.Reader, maxCiphertext, maxSnapshotBytes int64, maxObjects, maxReferences int, genericSet GenericSetEnvelope, genericTrust GenericSetRecovery, goSet GoSetEnvelope, goTrust GenericSetRecovery, cargoSet CargoSetEnvelope, cargoTrust GenericSetRecovery, npmSet NPMSetEnvelope, npmTrust GenericSetRecovery, parent, name string, genericSources, goSources, cargoSources, npmSources []RecoveryObjectSource, identity age.Identity, newStage func() (RecoveryStage, error)) (PreparedSQLiteRecovery, error) {
	return prepareEncryptedSQLiteFormatsRecovery(ctx, ciphertext, maxCiphertext, maxSnapshotBytes, maxObjects, maxReferences, genericSet, genericTrust, goSet, goTrust, &cargoSet, &cargoTrust, &npmSet, &npmTrust, nil, nil, parent, name, genericSources, goSources, cargoSources, npmSources, nil, identity, newStage)
}

// PrepareEncryptedSQLitePubRecovery restores generic, Go, Cargo, npm and Pub
// objects into a new isolated directory. The incomplete marker remains; keys,
// configuration, other formats and promotion are outside this operation.
func PrepareEncryptedSQLitePubRecovery(ctx context.Context, ciphertext io.Reader, maxCiphertext, maxSnapshotBytes int64, maxObjects, maxReferences int, genericSet GenericSetEnvelope, genericTrust GenericSetRecovery, goSet GoSetEnvelope, goTrust GenericSetRecovery, cargoSet CargoSetEnvelope, cargoTrust GenericSetRecovery, npmSet NPMSetEnvelope, npmTrust GenericSetRecovery, pubSet PubSetEnvelope, pubTrust GenericSetRecovery, parent, name string, genericSources, goSources, cargoSources, npmSources, pubSources []RecoveryObjectSource, identity age.Identity, newStage func() (RecoveryStage, error)) (PreparedSQLiteRecovery, error) {
	return prepareEncryptedSQLiteFormatsRecovery(ctx, ciphertext, maxCiphertext, maxSnapshotBytes, maxObjects, maxReferences, genericSet, genericTrust, goSet, goTrust, &cargoSet, &cargoTrust, &npmSet, &npmTrust, &pubSet, &pubTrust, parent, name, genericSources, goSources, cargoSources, npmSources, pubSources, identity, newStage)
}

func prepareEncryptedSQLiteFormatsRecovery(ctx context.Context, ciphertext io.Reader, maxCiphertext, maxSnapshotBytes int64, maxObjects, maxReferences int, genericSet GenericSetEnvelope, genericTrust GenericSetRecovery, goSet GoSetEnvelope, goTrust GenericSetRecovery, cargoSet *CargoSetEnvelope, cargoTrust *GenericSetRecovery, npmSet *NPMSetEnvelope, npmTrust *GenericSetRecovery, pubSet *PubSetEnvelope, pubTrust *GenericSetRecovery, parent, name string, genericSources, goSources, cargoSources, npmSources, pubSources []RecoveryObjectSource, identity age.Identity, newStage func() (RecoveryStage, error)) (result PreparedSQLiteRecovery, retErr error) {
	if ctx == nil || ciphertext == nil || identity == nil || newStage == nil {
		return result, errors.New("encrypted SQLite Go recovery parameters are invalid")
	}
	if genericTrust.InstallationID != goTrust.InstallationID || genericTrust.BackupID != goTrust.BackupID || genericTrust.SnapshotSHA256 != goTrust.SnapshotSHA256 {
		return result, errors.New("recovery set contexts do not match")
	}
	if _, err := VerifyGenericSet(genericSet, genericTrust.Signer, genericTrust.InstallationID, genericTrust.BackupID, genericTrust.SnapshotSHA256); err != nil {
		return result, err
	}
	if _, err := VerifyGoSet(goSet, goTrust.Signer, goTrust.InstallationID, goTrust.BackupID, goTrust.SnapshotSHA256); err != nil {
		return result, err
	}
	stage, err := newStage()
	if err != nil || stage == nil {
		if stage != nil {
			_ = stage.Close()
		}
		return result, errors.New("encrypted SQLite Go recovery staging could not be created")
	}
	closed := false
	defer func() {
		if !closed {
			if err := stage.Close(); err != nil {
				result = PreparedSQLiteRecovery{}
				retErr = errors.Join(retErr, errors.New("encrypted SQLite Go recovery staging could not be removed"))
			}
		}
	}()
	end, err := stage.Seek(0, io.SeekEnd)
	if err != nil || end != 0 {
		return result, errors.New("encrypted SQLite Go recovery staging must be empty")
	}
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		return result, errors.New("encrypted SQLite Go recovery staging cannot be rewound")
	}
	if _, err := DecryptSnapshot(ctx, ciphertext, stage, maxCiphertext, maxSnapshotBytes, genericTrust.SnapshotSHA256, identity); err != nil {
		return result, err
	}
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		return result, errors.New("encrypted SQLite Go recovery staging cannot be rewound")
	}
	prepared, err := prepareSQLiteRecovery(ctx, stage, maxSnapshotBytes, maxObjects, maxReferences, genericSet, genericTrust, &goSet, &goTrust, cargoSet, cargoTrust, npmSet, npmTrust, pubSet, pubTrust, parent, name)
	if err != nil {
		return result, err
	}
	closed = true
	if err := stage.Close(); err != nil {
		return result, errors.New("encrypted SQLite Go recovery staging could not be removed")
	}
	dir := filepath.Dir(prepared.DatabasePath)
	cfg := config.Config{DataDir: dir, DatabaseDriver: config.SQLite, DatabaseDSN: prepared.DatabasePath, DatabaseMaxOpenConns: 1}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		return result, errors.New("SQLite Go recovery catalog could not be opened")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		_ = db.Close()
		return result, errors.New("SQLite Go recovery inventory could not begin")
	}
	genericInventory, inventoryErr := InventoryGeneric(ctx, tx, maxObjects, maxReferences)
	var goInventory []GenericObject
	if inventoryErr == nil {
		goInventory, inventoryErr = InventoryGo(ctx, tx, maxObjects, maxReferences)
	}
	var cargoInventory []GenericObject
	if inventoryErr == nil && cargoSet != nil {
		cargoInventory, inventoryErr = InventoryCargo(ctx, tx, maxObjects, maxReferences)
	}
	var npmInventory []GenericObject
	if inventoryErr == nil && npmSet != nil {
		npmInventory, inventoryErr = InventoryNPM(ctx, tx, maxObjects, maxReferences)
	}
	var pubInventory []GenericObject
	if inventoryErr == nil && pubSet != nil {
		pubInventory, inventoryErr = InventoryPub(ctx, tx, maxObjects, maxReferences)
	}
	rollbackErr := tx.Rollback()
	closeErr := db.Close()
	if inventoryErr != nil || rollbackErr != nil || closeErr != nil {
		return result, errors.New("SQLite Go recovery inventory could not be read")
	}
	genericTrust.Inventory = genericInventory
	goTrust.Inventory = goInventory
	store, err := storage.NewFileSystem(filepath.Join(dir, "object-store"))
	if err != nil {
		return result, errors.New("SQLite Go recovery storage could not be created")
	}
	if err := RestoreGenericSet(ctx, genericSet, genericTrust, genericSources, identity, newStage, store); err != nil {
		return result, err
	}
	if err := RestoreGoSet(ctx, goSet, goTrust, goSources, identity, newStage, store); err != nil {
		return result, err
	}
	if cargoSet != nil {
		cargoTrust.Inventory = cargoInventory
		if err := RestoreCargoSet(ctx, *cargoSet, *cargoTrust, cargoSources, identity, newStage, store); err != nil {
			return result, err
		}
	}
	if npmSet != nil {
		npmTrust.Inventory = npmInventory
		if err := RestoreNPMSet(ctx, *npmSet, *npmTrust, npmSources, identity, newStage, store); err != nil {
			return result, err
		}
	}
	if pubSet != nil {
		pubTrust.Inventory = pubInventory
		if err := RestorePubSet(ctx, *pubSet, *pubTrust, pubSources, identity, newStage, store); err != nil {
			return result, err
		}
	}
	return prepared, nil
}
