package backup

import (
	"context"
	"database/sql"
	"errors"
)

// VerifySQLiteIntegrity checks SQLite's physical integrity and foreign keys.
// It must run on an isolated recovered database, not a live deployment. It is
// read-only but can consume substantial I/O; callers must set a deadline and
// enforce independent resource limits. Passing does not authenticate the
// snapshot or prove application-level recovery.
func VerifySQLiteIntegrity(ctx context.Context, db *sql.DB) (retErr error) {
	if ctx == nil || db == nil {
		return errors.New("SQLite recovery integrity verification is unavailable")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("SQLite recovery integrity verification requires a deadline")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return errors.New("SQLite recovery integrity transaction could not begin")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			retErr = errors.Join(retErr, errors.New("SQLite recovery integrity transaction could not close"))
		}
	}()
	var result string
	if err := tx.QueryRowContext(ctx, `PRAGMA integrity_check(1)`).Scan(&result); err != nil || result != "ok" {
		return errors.New("recovered SQLite database failed integrity check")
	}
	rows, err := tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return errors.New("recovered SQLite foreign keys could not be checked")
	}
	defer rows.Close()
	if rows.Next() {
		return errors.New("recovered SQLite database contains foreign key violations")
	}
	if err := rows.Err(); err != nil {
		return errors.New("recovered SQLite foreign keys could not be checked")
	}
	return nil
}
