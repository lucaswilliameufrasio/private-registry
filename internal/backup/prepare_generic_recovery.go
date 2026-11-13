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

// PrepareSQLiteGenericRecovery prepares an isolated SQLite catalog and its
// generic objects. It leaves RECOVERY_INCOMPLETE in place even on success: it
// is not a complete installation recovery and must not be promoted or served.
// Snapshot authentication, a private parent, private staging, source access,
// resource budgets and independent trust remain the caller's responsibility.
// Failures may leave a partial, owned recovery directory for inspection.
func PrepareSQLiteGenericRecovery(ctx context.Context, snapshot io.Reader, maxSnapshotBytes int64, maxObjects, maxReferences int, set GenericSetEnvelope, trusted GenericSetRecovery, parent, name string, sources []RecoveryObjectSource, identity age.Identity, newStage func() (RecoveryStage, error)) (PreparedSQLiteRecovery, error) {
	if identity == nil || newStage == nil {
		return PreparedSQLiteRecovery{}, errors.New("isolated generic recovery parameters are invalid")
	}
	prepared, err := PrepareSQLiteRecovery(ctx, snapshot, maxSnapshotBytes, maxObjects, maxReferences, set, trusted, parent, name)
	if err != nil {
		return PreparedSQLiteRecovery{}, err
	}
	dir := filepath.Dir(prepared.DatabasePath)
	cfg := config.Config{DataDir: dir, DatabaseDriver: config.SQLite, DatabaseDSN: prepared.DatabasePath, DatabaseMaxOpenConns: 1}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		return PreparedSQLiteRecovery{}, errors.New("isolated generic recovery catalog could not be opened")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		_ = db.Close()
		return PreparedSQLiteRecovery{}, errors.New("isolated generic recovery inventory could not begin")
	}
	inventory, inventoryErr := InventoryGeneric(ctx, tx, maxObjects, maxReferences)
	rollbackErr := tx.Rollback()
	closeErr := db.Close()
	if inventoryErr != nil || rollbackErr != nil || closeErr != nil {
		return PreparedSQLiteRecovery{}, errors.New("isolated generic recovery inventory could not be read")
	}
	trusted.Inventory = inventory
	store, err := storage.NewFileSystem(filepath.Join(dir, "object-store"))
	if err != nil {
		return PreparedSQLiteRecovery{}, errors.New("isolated generic recovery storage could not be created")
	}
	if err := RestoreGenericSet(ctx, set, trusted, sources, identity, newStage, store); err != nil {
		return PreparedSQLiteRecovery{}, err
	}
	return prepared, nil
}
