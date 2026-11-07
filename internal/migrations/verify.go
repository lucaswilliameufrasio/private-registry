package migrations

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	"private-registry/internal/config"
)

// VerifyCurrent checks the embedded migration history and checksums without
// applying migrations or changing records. It conservatively rejects rollback
// records and in-progress migrations. It does not prove the physical schema or
// database content was not altered, and must not be treated as snapshot trust.
func VerifyCurrent(ctx context.Context, db *sql.DB, driver config.DatabaseDriver, expectedInstallationID string) (retErr error) {
	if ctx == nil || db == nil || (driver != config.SQLite && driver != config.Postgres) {
		return errors.New("database schema verification parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("database schema verification requires a deadline")
	}
	installation, err := uuid.Parse(expectedInstallationID)
	if err != nil || installation.String() != expectedInstallationID {
		return errors.New("expected installation identity is invalid")
	}
	engineFS, err := fs.Sub(embeddedMigrations, "sql/"+string(driver))
	if err != nil {
		return errors.New("embedded database migrations are unavailable")
	}
	dialect := goose.DialectSQLite3
	if driver == config.Postgres {
		dialect = goose.DialectPostgres
	}
	provider, err := goose.NewProvider(dialect, db, engineFS, goose.WithDisableGlobalRegistry(true), goose.WithLogger(goose.NopLogger()))
	if err != nil {
		return errors.New("embedded database migrations could not be loaded")
	}
	sources := provider.ListSources()
	checksums, err := migrationChecksums(engineFS, sources)
	if err != nil || len(checksums) == 0 {
		return errors.New("embedded database migration checksums are unavailable")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return errors.New("database schema verification transaction could not begin")
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			retErr = errors.Join(retErr, errors.New("database schema verification transaction could not close"))
		}
	}()
	var actualID string
	if err := tx.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&actualID); err != nil || actualID != expectedInstallationID {
		return errors.New("recovered database installation identity does not match")
	}
	applied, err := readAppliedVersions(ctx, tx)
	if err != nil || len(applied) != len(checksums) {
		return errors.New("recovered database migration history does not match")
	}
	stored, err := readChecksums(ctx, tx)
	if err != nil || len(stored) != len(checksums) {
		return errors.New("recovered database migration checksums do not match")
	}
	for version, checksum := range checksums {
		if _, ok := applied[version]; !ok || stored[version] != checksum {
			return errors.New("recovered database migration history or checksum does not match")
		}
	}
	var unsafeHistory bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM goose_db_version WHERE version_id > 0 AND is_applied = FALSE)`).Scan(&unsafeHistory); err != nil || unsafeHistory {
		return errors.New("recovered database has unsupported rollback history")
	}
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_migration_attempts WHERE status = 'running')`).Scan(&unsafeHistory); err != nil || unsafeHistory {
		return errors.New("recovered database has an incomplete migration attempt")
	}
	return nil
}
