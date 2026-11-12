package database

import (
	"context"
	"database/sql"
	"errors"

	"private-registry/internal/config"
)

// ReserveWrite takes SQLite's write lock at the start of a transaction that
// reads before it writes. A deferred SQLite transaction that has already read
// cannot wait for the write lock: under concurrency its first write fails at
// once with SQLITE_BUSY instead of honouring busy_timeout. Writing first makes
// the transaction wait for the lock like any other writer. PostgreSQL needs
// no reservation, so the call does nothing there.
func ReserveWrite(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver) error {
	if driver != config.SQLite {
		return nil
	}
	if ctx == nil || tx == nil {
		return errors.New("database write reservation is unavailable")
	}
	result, err := tx.ExecContext(ctx, "UPDATE registry_installation SET repository_visibility_policy = repository_visibility_policy WHERE singleton_id = 1")
	if err != nil {
		return errors.New("database write lock could not be acquired")
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		return errors.New("installation coordination row is unavailable")
	}
	return nil
}
