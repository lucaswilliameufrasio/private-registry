package repositories

import (
	"context"
	"database/sql"
	"errors"

	"private-registry/internal/config"
)

var ErrReviewRequired = errors.New("publication requires human review")

// RequireFormat checks a repository's immutable format. The caller must first
// authorize the actor; this helper does not grant access or serialize writes.
func RequireFormat(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, driver config.DatabaseDriver, workspaceID, repositoryID string, expected Format) error {
	if ctx == nil || queryer == nil || (driver != config.SQLite && driver != config.Postgres) || (expected != FormatGeneric && expected != FormatGo) {
		return errors.New("repository format check is unavailable")
	}
	query := `SELECT format FROM registry_repositories WHERE workspace_id = ` + bind(driver, 1) + ` AND repository_id = ` + bind(driver, 2) + ` AND status = 'active'`
	var actual string
	if err := queryer.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&actual); errors.Is(err, sql.ErrNoRows) {
		return ErrRepositoryUnavailable
	} else if err != nil {
		return errors.New("repository format could not be checked")
	}
	if actual != string(expected) {
		return ErrFormatMismatch
	}
	return nil
}

// RequireNoReview is a fail-closed boundary until reviewed publication is
// implemented. The caller must authorize and hold the shared write lock.
func RequireNoReview(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, workspaceID, repositoryID string) error {
	if ctx == nil || tx == nil || (driver != config.SQLite && driver != config.Postgres) {
		return errors.New("repository review policy check is unavailable")
	}
	query := `SELECT review_required FROM registry_repositories WHERE workspace_id = ` + bind(driver, 1) + ` AND repository_id = ` + bind(driver, 2) + ` AND status = 'active'`
	var required int
	if err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&required); err != nil {
		return errors.New("repository review policy could not be checked")
	}
	if required != 0 {
		return ErrReviewRequired
	}
	return nil
}
