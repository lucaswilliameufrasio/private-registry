package repositories

import (
	"context"
	"database/sql"
	"errors"

	"private-registry/internal/config"
	"private-registry/internal/workspaces"
)

var ErrReviewRequired = errors.New("publication requires human review")

// RequireFormat checks a repository's immutable format. The caller must first
// authorize the actor; this helper does not grant access or serialize writes.
func RequireFormat(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, driver config.DatabaseDriver, workspaceID, repositoryID string, expected Format) error {
	if ctx == nil || queryer == nil || (driver != config.SQLite && driver != config.Postgres) || !knownFormat(expected) {
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

// WithRepositoryManagerTransaction runs operation for an active owner or
// administrator of the repository's workspace, after checking the
// repository's format, under the shared authorization lock. It is for
// management actions that repository grants alone must not allow, such as
// removing published content or changing a repository's publication rules.
func (s *Service) WithRepositoryManagerTransaction(ctx context.Context, actorUserID, workspaceID, repositoryID string, format Format, operation func(*sql.Tx, string) error) error {
	if s == nil || s.db == nil || ctx == nil || operation == nil {
		return errors.New("repository management transaction is unavailable")
	}
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return ErrInvalidWorkspaceID
	}
	repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
	if err != nil {
		return ErrInvalidRepositoryID
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		role, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID)
		if err != nil {
			return err
		}
		if role != workspaces.RoleOwner && role != workspaces.RoleAdministrator {
			return ErrForbidden
		}
		if err := RequireFormat(ctx, tx, s.driver, workspaceID, repositoryID, format); err != nil {
			return err
		}
		return operation(tx, actorID)
	})
}

// RecordAudit appends one succeeded audit event inside the caller's
// transaction.
func RecordAudit(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, actorUserID, action, targetType, targetID string) error {
	return recordAudit(ctx, tx, driver, actorUserID, action, targetType, targetID)
}
