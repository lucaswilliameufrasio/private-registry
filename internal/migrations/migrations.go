package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	"private-registry/internal/config"
)

const (
	checksumTable = "registry_migration_checksums"
	attemptTable  = "registry_migration_attempts"
	gooseTable    = "goose_db_version"
)

//go:embed sql/*/*.sql
var embeddedMigrations embed.FS

type Report struct {
	AppliedVersions []int64
	CurrentVersion  int64
	TargetVersion   int64
	InstallationID  string
}

type migrationQueryer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func Migrate(ctx context.Context, db *sql.DB, cfg config.Config) (report Report, retErr error) {
	return migrateWithFS(ctx, db, cfg, embeddedMigrations)
}

func migrateWithFS(
	ctx context.Context,
	db *sql.DB,
	cfg config.Config,
	root fs.FS,
) (report Report, retErr error) {
	if ctx == nil || db == nil || root == nil {
		return Report{}, errors.New("migration context, database, and migration filesystem are required")
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	if cfg.DatabaseDriver != config.SQLite && cfg.DatabaseDriver != config.Postgres {
		return Report{}, errors.New("migration driver must be sqlite or postgres")
	}

	driver := cfg.DatabaseDriver
	engineFS, err := fs.Sub(root, "sql/"+string(driver))
	if err != nil {
		return Report{}, errors.New("migration directory is unavailable for the selected database")
	}
	dialect := goose.DialectSQLite3
	if driver == config.Postgres {
		dialect = goose.DialectPostgres
	}
	provider, err := goose.NewProvider(dialect, db, engineFS,
		goose.WithDisableGlobalRegistry(true), goose.WithLogger(goose.NopLogger()))
	if err != nil {
		return Report{}, errors.New("database migrations could not be loaded")
	}

	sources := provider.ListSources()
	if len(sources) == 0 {
		return Report{}, errors.New("no database migrations are embedded for the selected driver")
	}
	checksums, err := migrationChecksums(engineFS, sources)
	if err != nil {
		return Report{}, err
	}

	unlock, err := acquireMigrationLock(ctx, db, driver, cfg.DatabaseDSN)
	if err != nil {
		return Report{}, err
	}
	defer func() {
		retErr = errors.Join(retErr, unlock())
	}()

	if err := prepareMigrationMetadata(ctx, db, driver, checksums); err != nil {
		return Report{}, err
	}
	statuses, err := provider.Status(ctx)
	if err != nil {
		return Report{}, errors.New("database migration history could not be read")
	}
	if err := reconcileInterruptedAttempts(ctx, db, driver); err != nil {
		return Report{}, err
	}

	for {
		pending, err := provider.HasPending(ctx)
		if err != nil {
			return Report{}, errors.New("database migration state could not be checked")
		}
		if !pending {
			break
		}
		version, err := nextPendingVersion(statuses)
		if err != nil {
			return Report{}, err
		}
		attemptID, err := startAttempt(ctx, db, driver, version)
		if err != nil {
			return Report{}, errors.New("database migration attempt could not be recorded")
		}
		var migrationErr error
		if driver == config.SQLite && (version == 18 || version == 25 || version == 33) {
			migrationErr = runSQLiteRepositoryRebuild(ctx, cfg, engineFS, version)
		} else {
			_, migrationErr = provider.UpByOne(ctx)
		}
		if migrationErr != nil {
			markErr := finishAttempt(ctx, db, driver, attemptID, "failed", "migration_failed")
			return Report{}, errors.Join(fmt.Errorf("database migration %d failed", version), migrationErr, markErr)
		}
		if err := finishAttempt(ctx, db, driver, attemptID, "succeeded", ""); err != nil {
			return Report{}, fmt.Errorf("database migration %d succeeded but its attempt history could not be finalized", version)
		}
		report.AppliedVersions = append(report.AppliedVersions, version)
		statuses, err = provider.Status(ctx)
		if err != nil {
			return Report{}, errors.New("database migration history could not be refreshed")
		}
	}

	installationID, err := ensureInstallation(ctx, db, driver)
	if err != nil {
		return Report{}, err
	}
	currentVersion, err := provider.GetDBVersion(ctx)
	if err != nil {
		return Report{}, errors.New("database schema version could not be read")
	}
	for _, source := range sources {
		if source.Version > report.TargetVersion {
			report.TargetVersion = source.Version
		}
	}
	report.CurrentVersion = currentVersion
	report.InstallationID = installationID
	return report, nil
}

func migrationChecksums(engineFS fs.FS, sources []*goose.Source) (map[int64]string, error) {
	checksums := make(map[int64]string, len(sources))
	for _, source := range sources {
		if source == nil || source.Type != goose.TypeSQL || source.Version < 1 || source.Path == "" {
			return nil, errors.New("migrations must be versioned SQL files")
		}
		contents, err := fs.ReadFile(engineFS, source.Path)
		if err != nil {
			return nil, errors.New("migration source could not be read")
		}
		if strings.Contains(strings.ToUpper(string(contents)), "+GOOSE NO TRANSACTION") {
			return nil, fmt.Errorf("migration %d requests unsupported non-transactional execution", source.Version)
		}
		digest := sha256.Sum256(contents)
		checksums[source.Version] = hex.EncodeToString(digest[:])
	}
	return checksums, nil
}

func prepareMigrationMetadata(
	ctx context.Context,
	db *sql.DB,
	driver config.DatabaseDriver,
	checksums map[int64]string,
) (retErr error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("migration metadata transaction could not begin")
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			retErr = errors.Join(retErr, rollbackErr)
		}
	}()

	hasGooseHistory, err := tableExists(ctx, tx, driver, gooseTable)
	if err != nil {
		return errors.New("database migration history could not be inspected")
	}
	hasChecksumHistory, err := tableExists(ctx, tx, driver, checksumTable)
	if err != nil {
		return errors.New("migration checksum history could not be inspected")
	}
	appliedVersions := make(map[int64]struct{})
	if hasGooseHistory {
		appliedVersions, err = readAppliedVersions(ctx, tx)
		if err != nil {
			return errors.New("applied database migrations could not be inspected")
		}
	}
	if len(appliedVersions) > 0 && !hasChecksumHistory {
		return errors.New("existing applied migrations have no verifiable checksum history")
	}

	storedChecksums := make(map[int64]string)
	if hasChecksumHistory {
		storedChecksums, err = readChecksums(ctx, tx)
		if err != nil {
			return errors.New("migration checksum history could not be read")
		}
	}
	for version := range appliedVersions {
		if _, ok := storedChecksums[version]; !ok {
			return fmt.Errorf("applied migration %d has no recorded checksum", version)
		}
	}
	for version, stored := range storedChecksums {
		expected, ok := checksums[version]
		if !ok {
			return fmt.Errorf("migration %d is recorded in the database but missing from this binary", version)
		}
		if stored != expected {
			return fmt.Errorf("migration %d checksum does not match the applied source", version)
		}
	}

	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+checksumTable+` (
		version_id BIGINT PRIMARY KEY,
		checksum TEXT NOT NULL CHECK (length(checksum) = 64)
	)`); err != nil {
		return errors.New("migration checksum table could not be created")
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+attemptTable+` (
		attempt_id TEXT PRIMARY KEY,
		version_id BIGINT NOT NULL,
		status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed', 'interrupted')),
		started_at TEXT NOT NULL,
		finished_at TEXT,
		failure_code TEXT
	)`); err != nil {
		return errors.New("migration attempt table could not be created")
	}
	for version, checksum := range checksums {
		if _, ok := storedChecksums[version]; ok {
			continue
		}
		query := `INSERT INTO registry_migration_checksums (version_id, checksum) VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `)`
		if _, err := tx.ExecContext(ctx, query, version, checksum); err != nil {
			return errors.New("migration checksum could not be recorded")
		}
	}
	if err := tx.Commit(); err != nil {
		return errors.New("migration metadata transaction could not commit")
	}
	return nil
}

func tableExists(ctx context.Context, queryer migrationQueryer, driver config.DatabaseDriver, table string) (bool, error) {
	if driver == config.SQLite {
		var exists bool
		err := queryer.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)", table).Scan(&exists)
		return exists, err
	}
	var exists bool
	err := queryer.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", table).Scan(&exists)
	return exists, err
}

func readAppliedVersions(ctx context.Context, queryer migrationQueryer) (map[int64]struct{}, error) {
	rows, err := queryer.QueryContext(ctx,
		"SELECT version_id FROM "+gooseTable+" WHERE version_id > 0 AND is_applied = TRUE")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	versions := make(map[int64]struct{})
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		versions[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return versions, nil
}

func readChecksums(ctx context.Context, queryer migrationQueryer) (map[int64]string, error) {
	rows, err := queryer.QueryContext(ctx, "SELECT version_id, checksum FROM "+checksumTable)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	checksums := make(map[int64]string)
	for rows.Next() {
		var version int64
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, err
		}
		checksums[version] = checksum
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return checksums, nil
}

func nextPendingVersion(statuses []*goose.MigrationStatus) (int64, error) {
	for _, status := range statuses {
		if status != nil && status.State == goose.StatePending && status.Source != nil {
			return status.Source.Version, nil
		}
	}
	return 0, errors.New("database reports pending migrations without a pending source")
}

func reconcileInterruptedAttempts(ctx context.Context, db *sql.DB, driver config.DatabaseDriver) error {
	rows, err := db.QueryContext(ctx,
		"SELECT attempt_id, version_id FROM "+attemptTable+" WHERE status = 'running' ORDER BY started_at, attempt_id")
	if err != nil {
		return errors.New("unfinished migration attempts could not be read")
	}
	type unfinishedAttempt struct {
		id      string
		version int64
	}
	var attempts []unfinishedAttempt
	for rows.Next() {
		var attempt unfinishedAttempt
		if err := rows.Scan(&attempt.id, &attempt.version); err != nil {
			_ = rows.Close()
			return errors.New("unfinished migration attempt could not be decoded")
		}
		attempts = append(attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return errors.New("unfinished migration attempts could not be read")
	}
	if err := rows.Close(); err != nil {
		return errors.New("unfinished migration attempts could not be closed")
	}

	for _, attempt := range attempts {
		applied, err := migrationIsApplied(ctx, db, driver, attempt.version)
		if err != nil {
			return errors.New("unfinished migration state could not be reconciled")
		}
		status := "interrupted"
		failureCode := "interrupted"
		if applied {
			status = "succeeded"
			failureCode = ""
		}
		if err := finishAttempt(ctx, db, driver, attempt.id, status, failureCode); err != nil {
			return errors.New("unfinished migration attempt could not be reconciled")
		}
	}
	return nil
}

func migrationIsApplied(ctx context.Context, db *sql.DB, driver config.DatabaseDriver, version int64) (bool, error) {
	var applied bool
	query := "SELECT is_applied FROM " + gooseTable + " WHERE version_id = " + bind(driver, 1) + " ORDER BY tstamp DESC LIMIT 1"
	err := db.QueryRowContext(ctx, query, version).Scan(&applied)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return applied, err
}

func startAttempt(ctx context.Context, db *sql.DB, driver config.DatabaseDriver, version int64) (string, error) {
	attemptID, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	query := `INSERT INTO ` + attemptTable + ` (attempt_id, version_id, status, started_at)
		VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, ` + bind(driver, 3) + `, ` + bind(driver, 4) + `)`
	_, err = db.ExecContext(ctx, query, attemptID.String(), version, "running", time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return "", err
	}
	return attemptID.String(), nil
}

func finishAttempt(ctx context.Context, db *sql.DB, driver config.DatabaseDriver, attemptID, status, failureCode string) error {
	var failure any
	if failureCode != "" {
		failure = failureCode
	}
	query := `UPDATE ` + attemptTable + `
		SET status = ` + bind(driver, 1) + `, finished_at = ` + bind(driver, 2) + `, failure_code = ` + bind(driver, 3) + `
		WHERE attempt_id = ` + bind(driver, 4) + ` AND status = 'running'`
	result, err := db.ExecContext(ctx, query, status, time.Now().UTC().Format(time.RFC3339Nano), failure, attemptID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected != 1 {
		return errors.New("migration attempt is not in the running state")
	}
	return nil
}

func ensureInstallation(ctx context.Context, db *sql.DB, driver config.DatabaseDriver) (string, error) {
	var installationID string
	err := db.QueryRowContext(ctx,
		"SELECT installation_id FROM registry_installation WHERE singleton_id = 1").Scan(&installationID)
	if err == nil {
		parsed, parseErr := uuid.Parse(installationID)
		if parseErr != nil || parsed.Version() != 7 {
			return "", errors.New("stored installation identifier is not a valid UUIDv7")
		}
		return installationID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("installation identity could not be read")
	}
	newID, err := uuid.NewV7()
	if err != nil {
		return "", errors.New("installation identity could not be generated")
	}
	query := `INSERT INTO registry_installation (singleton_id, installation_id, created_at)
		VALUES (1, ` + bind(driver, 1) + `, ` + bind(driver, 2) + `)`
	_, err = db.ExecContext(ctx, query, newID.String(), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return "", errors.New("installation identity could not be persisted")
	}
	return newID.String(), nil
}

func bind(driver config.DatabaseDriver, position int) string {
	if driver == config.Postgres {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}
