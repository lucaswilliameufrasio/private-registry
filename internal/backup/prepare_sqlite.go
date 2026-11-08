package backup

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
)

var recoveryDirectoryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// PreparedSQLiteRecovery describes an unpromoted, isolated database copy.
// It does not mean the installation, objects, secrets or backup are complete.
type PreparedSQLiteRecovery struct {
	DatabasePath       string
	SnapshotSize       int64
	GenericObjects     int
	GoObjects          int
	CargoObjects       int
	Invalidated        InvalidatedCredentials
	HeldJobs           int64
	InvalidatedUploads int64
}

// PrepareSQLiteRecovery writes an authenticated plaintext SQLite snapshot to a
// new private directory beneath an exclusively controlled private parent. It
// checks the signed generic-set context, snapshot digest, SQLite integrity,
// migration history and installation identity, then transactionally invalidates
// old credentials. No existing directory is reused or overwritten. Any failure
// after creation leaves an owned incomplete directory for operator inspection;
// callers must never promote it. A RECOVERY_INCOMPLETE marker remains on success
// too: this operation does not recover objects or authorize starting a server.
// The caller must authenticate and decrypt the complete encrypted snapshot
// before passing it, enforce resource budgets and protect the trusted parent.
func PrepareSQLiteRecovery(ctx context.Context, snapshot io.Reader, maxSnapshotBytes int64, maxObjects, maxReferences int, setEnvelope GenericSetEnvelope, trusted GenericSetRecovery, parent, name string) (result PreparedSQLiteRecovery, retErr error) {
	return prepareSQLiteRecovery(ctx, snapshot, maxSnapshotBytes, maxObjects, maxReferences, setEnvelope, trusted, nil, nil, nil, nil, parent, name)
}

func prepareSQLiteRecovery(ctx context.Context, snapshot io.Reader, maxSnapshotBytes int64, maxObjects, maxReferences int, setEnvelope GenericSetEnvelope, trusted GenericSetRecovery, goEnvelope *GoSetEnvelope, trustedGo *GenericSetRecovery, cargoEnvelope *CargoSetEnvelope, trustedCargo *GenericSetRecovery, parent, name string) (result PreparedSQLiteRecovery, retErr error) {
	if ctx == nil || snapshot == nil || maxSnapshotBytes < 1 || maxSnapshotBytes > 1<<40 || maxObjects < 1 || maxObjects > maxGenericSetObjects || maxReferences < 1 || maxReferences > 10000000 || !filepath.IsAbs(parent) || !recoveryDirectoryName.MatchString(name) {
		return result, errors.New("isolated SQLite recovery parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return result, errors.New("isolated SQLite recovery requires a deadline")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if _, err := VerifyGenericSet(setEnvelope, trusted.Signer, trusted.InstallationID, trusted.BackupID, trusted.SnapshotSHA256); err != nil {
		return result, err
	}
	if (goEnvelope == nil) != (trustedGo == nil) {
		return result, errors.New("Go recovery set and trust must be supplied together")
	}
	if goEnvelope != nil {
		if trustedGo.InstallationID != trusted.InstallationID || trustedGo.BackupID != trusted.BackupID || trustedGo.SnapshotSHA256 != trusted.SnapshotSHA256 {
			return result, errors.New("Go recovery context does not match snapshot context")
		}
		if _, err := VerifyGoSet(*goEnvelope, trustedGo.Signer, trustedGo.InstallationID, trustedGo.BackupID, trustedGo.SnapshotSHA256); err != nil {
			return result, err
		}
	}
	if (cargoEnvelope == nil) != (trustedCargo == nil) {
		return result, errors.New("Cargo recovery set and trust must be supplied together")
	}
	if cargoEnvelope != nil {
		if trustedCargo.InstallationID != trusted.InstallationID || trustedCargo.BackupID != trusted.BackupID || trustedCargo.SnapshotSHA256 != trusted.SnapshotSHA256 {
			return result, errors.New("Cargo recovery context does not match snapshot context")
		}
		if _, err := VerifyCargoSet(*cargoEnvelope, trustedCargo.Signer, trustedCargo.InstallationID, trustedCargo.BackupID, trustedCargo.SnapshotSHA256); err != nil {
			return result, err
		}
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		return result, errors.New("SQLite recovery parent must be an existing private directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return result, errors.New("SQLite recovery parent could not be opened")
	}
	defer func() {
		if err := root.Close(); err != nil {
			retErr = errors.Join(retErr, errors.New("SQLite recovery parent could not be closed"))
			result = PreparedSQLiteRecovery{}
		}
	}()
	if err := root.Mkdir(name, 0o700); err != nil {
		return result, errors.New("SQLite recovery destination must not already exist")
	}
	marker, err := root.OpenFile(filepath.Join(name, "RECOVERY_INCOMPLETE"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return result, errors.New("SQLite recovery marker could not be created")
	}
	if err := marker.Close(); err != nil {
		return result, errors.New("SQLite recovery marker could not be closed")
	}
	file, err := root.OpenFile(filepath.Join(name, "registry.sqlite"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return result, errors.New("SQLite recovery snapshot destination could not be created")
	}
	digest, size, digestErr := DigestSnapshot(ctx, io.TeeReader(snapshot, file), maxSnapshotBytes)
	if digestErr == nil && digest == trusted.SnapshotSHA256 {
		digestErr = file.Sync()
	} else if digestErr == nil {
		digestErr = errors.New("recovered snapshot digest does not match signed context")
	}
	closeErr := file.Close()
	if digestErr != nil || closeErr != nil {
		return result, errors.New("SQLite recovery snapshot could not be verified and staged")
	}
	dataDir := filepath.Join(parent, name)
	path := filepath.Join(dataDir, "registry.sqlite")
	cfg := config.Config{DataDir: dataDir, DatabaseDriver: config.SQLite, DatabaseDSN: path, DatabaseMaxOpenConns: 1}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		return result, errors.New("isolated SQLite recovery database could not be opened")
	}
	defer func() {
		if err := db.Close(); err != nil {
			retErr = errors.Join(retErr, errors.New("isolated SQLite recovery database could not be closed"))
			result = PreparedSQLiteRecovery{}
		}
	}()
	if err := VerifySQLiteIntegrity(ctx, db); err != nil {
		return result, err
	}
	if err := migrations.VerifyCurrent(ctx, db, config.SQLite, trusted.InstallationID); err != nil {
		return result, err
	}
	inventoryTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return result, errors.New("isolated SQLite recovery inventory could not begin")
	}
	inventory, inventoryErr := InventoryGeneric(ctx, inventoryTx, maxObjects, maxReferences)
	var goInventory []GenericObject
	if inventoryErr == nil {
		goInventory, inventoryErr = InventoryGo(ctx, inventoryTx, maxObjects, maxReferences)
	}
	var cargoInventory []GenericObject
	if inventoryErr == nil {
		cargoInventory, inventoryErr = InventoryCargo(ctx, inventoryTx, maxObjects, maxReferences)
	}
	var hasNPMVersions bool
	if inventoryErr == nil {
		inventoryErr = inventoryTx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_npm_versions UNION ALL SELECT 1 FROM registry_npm_reservations WHERE object_verified = 1)`).Scan(&hasNPMVersions)
	}
	rollbackErr := inventoryTx.Rollback()
	if inventoryErr != nil || rollbackErr != nil {
		return result, errors.New("isolated SQLite recovery inventory could not be verified")
	}
	if hasNPMVersions {
		return result, errors.New("partial recovery cannot prepare a catalog containing npm versions")
	}
	if cargoEnvelope == nil && len(cargoInventory) > 0 {
		return result, errors.New("partial recovery cannot prepare a catalog containing Cargo versions")
	}
	if cargoEnvelope != nil {
		if _, err := VerifyCargoSetInventory(*cargoEnvelope, trustedCargo.Signer, trustedCargo.InstallationID, trustedCargo.BackupID, digest, cargoInventory); err != nil {
			return result, err
		}
	}
	if _, err := VerifyGenericSetInventory(setEnvelope, trusted.Signer, trusted.InstallationID, trusted.BackupID, digest, inventory); err != nil {
		return result, err
	}
	if goEnvelope == nil && len(goInventory) > 0 {
		return result, errors.New("generic-only recovery cannot prepare a catalog containing Go modules")
	}
	if goEnvelope != nil {
		if _, err := VerifyGoSetInventory(*goEnvelope, trustedGo.Signer, trustedGo.InstallationID, trustedGo.BackupID, digest, goInventory); err != nil {
			return result, err
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return result, errors.New("isolated SQLite recovery transaction could not begin")
	}
	defer tx.Rollback()
	invalidated, err := InvalidateRestoredCredentials(ctx, tx, config.SQLite, time.Now())
	if err != nil {
		return result, err
	}
	heldJobs, err := HoldRestoredJobs(ctx, tx, config.SQLite, time.Now())
	if err != nil {
		return result, err
	}
	invalidatedUploads, err := InvalidateRestoredUploads(ctx, tx, config.SQLite, time.Now())
	if err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, errors.New("isolated SQLite recovery transaction could not commit")
	}
	return PreparedSQLiteRecovery{DatabasePath: path, SnapshotSize: size, GenericObjects: len(inventory), GoObjects: len(goInventory), CargoObjects: len(cargoInventory), Invalidated: invalidated, HeldJobs: heldJobs, InvalidatedUploads: invalidatedUploads}, nil
}
