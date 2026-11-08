package migrations

import (
	"context"
	"errors"
	"io/fs"

	"github.com/pressly/goose/v3"
	"private-registry/internal/config"
	"private-registry/internal/database"
)

// runSQLiteRepositoryRebuild uses a private, single-connection pool so the
// temporary SQLite pragmas cannot leak into the application's pool. Goose
// still executes the SQL and version record in one transaction; the SQL
// checks the pragmas and foreign keys before allowing that transaction to
// commit. The migration lock and the requirement to stop the server remain in
// force. Closing this private pool destroys the pragma-bearing connection.
func runSQLiteRepositoryRebuild(ctx context.Context, cfg config.Config, engineFS fs.FS) (retErr error) {
	db, err := database.Open(ctx, cfg)
	if err != nil {
		return errors.New("dedicated SQLite migration connection could not be opened")
	}
	defer func() {
		if err := db.Close(); err != nil {
			retErr = errors.Join(retErr, errors.New("dedicated SQLite migration connection could not be closed"))
		}
	}()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		return errors.New("dedicated SQLite migration connection could not be configured")
	}
	if _, err := db.ExecContext(ctx, `PRAGMA legacy_alter_table=ON`); err != nil {
		return errors.New("dedicated SQLite migration connection could not be configured")
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, engineFS, goose.WithDisableGlobalRegistry(true), goose.WithLogger(goose.NopLogger()))
	if err != nil {
		return errors.New("dedicated SQLite migration provider could not be created")
	}
	statuses, err := provider.Status(ctx)
	if err != nil {
		return errors.New("dedicated SQLite migration state could not be checked")
	}
	next, err := nextPendingVersion(statuses)
	if err != nil || next != 18 {
		return errors.New("dedicated SQLite migration is not the expected next version")
	}
	result, err := provider.UpByOne(ctx)
	if err != nil {
		return err
	}
	if result == nil || result.Source == nil || result.Source.Version != 18 {
		return errors.New("dedicated SQLite migration applied an unexpected version")
	}
	return nil
}
