package repositories

import (
	"context"
	"database/sql"
	"errors"
	"math"
)

var (
	ErrInvalidQuota  = errors.New("logical quota policy is invalid")
	ErrQuotaRevision = errors.New("logical quota policy revision is stale")
)

type LogicalQuota struct {
	LimitBytes *int64
	Revision   int64
}

// LogicalQuotaPolicy exposes policy metadata only to installation admins. It
// does not grant access to workspace contents or individual package metadata.
func (s *Service) LogicalQuotaPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string) (LogicalQuota, error) {
	var policy LogicalQuota
	err := s.withQuotaTarget(ctx, actorUserID, workspaceID, repositoryID, func(tx *sql.Tx, query string, args []any) error {
		var limit sql.NullInt64
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&limit, &policy.Revision); errors.Is(err, sql.ErrNoRows) {
			return ErrRepositoryUnavailable
		} else if err != nil {
			return errors.New("logical quota policy could not be read")
		}
		if limit.Valid {
			policy.LimitBytes = &limit.Int64
		}
		return nil
	})
	return policy, err
}

// SetLogicalQuotaPolicy is a compare-and-swap update. A nil limit explicitly
// disables the cap; zero is a valid cap. Existing content is never deleted.
func (s *Service) SetLogicalQuotaPolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string, expectedRevision int64, limit *int64) (LogicalQuota, error) {
	if expectedRevision < 0 || expectedRevision == math.MaxInt64 || (limit != nil && *limit < 0) {
		return LogicalQuota{}, ErrInvalidQuota
	}
	var err error
	actorUserID, err = parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return LogicalQuota{}, ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return LogicalQuota{}, ErrInvalidWorkspaceID
	}
	if repositoryID != "" {
		repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
		if err != nil {
			return LogicalQuota{}, ErrInvalidRepositoryID
		}
	}
	var policy LogicalQuota
	err = s.withQuotaTarget(ctx, actorUserID, workspaceID, repositoryID, func(tx *sql.Tx, query string, args []any) error {
		var old sql.NullInt64
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&old, &policy.Revision); errors.Is(err, sql.ErrNoRows) {
			return ErrRepositoryUnavailable
		} else if err != nil {
			return errors.New("logical quota policy could not be read")
		}
		if policy.Revision != expectedRevision {
			return ErrQuotaRevision
		}
		if (limit == nil && !old.Valid) || (limit != nil && old.Valid && *limit == old.Int64) {
			policy.LimitBytes = limit
			return nil
		}
		table, where, targetType, targetID := "registry_workspaces", "workspace_id", "workspace", workspaceID
		if repositoryID != "" {
			table, where, targetType, targetID = "registry_repositories", "repository_id", "repository", repositoryID
		}
		update := `UPDATE ` + table + ` SET logical_quota_bytes = ` + bind(s.driver, 1) + `, logical_quota_revision = logical_quota_revision + 1 WHERE ` + where + ` = ` + bind(s.driver, 2) + ` AND logical_quota_revision = ` + bind(s.driver, 3)
		result, err := tx.ExecContext(ctx, update, limit, targetID, expectedRevision)
		if err != nil {
			return errors.New("logical quota policy could not be changed")
		}
		if count, err := result.RowsAffected(); err != nil || count != 1 {
			return ErrQuotaRevision
		}
		if err := recordAudit(ctx, tx, s.driver, actorUserID, "logical_quota.changed", targetType, targetID); err != nil {
			return err
		}
		policy.Revision++
		policy.LimitBytes = limit
		return nil
	})
	return policy, err
}

func (s *Service) withQuotaTarget(ctx context.Context, actorUserID, workspaceID, repositoryID string, operation func(*sql.Tx, string, []any) error) error {
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return ErrInvalidWorkspaceID
	}
	if repositoryID != "" {
		repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
		if err != nil {
			return ErrInvalidRepositoryID
		}
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveAdministrator(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		query := `SELECT logical_quota_bytes, logical_quota_revision FROM registry_workspaces WHERE workspace_id = ` + bind(s.driver, 1) + ` AND status = 'active'`
		args := []any{workspaceID}
		if repositoryID != "" {
			query = `SELECT r.logical_quota_bytes, r.logical_quota_revision FROM registry_repositories r JOIN registry_workspaces w ON w.workspace_id = r.workspace_id WHERE r.workspace_id = ` + bind(s.driver, 1) + ` AND r.repository_id = ` + bind(s.driver, 2) + ` AND r.status = 'active' AND w.status = 'active'`
			args = append(args, repositoryID)
		}
		return operation(tx, query, args)
	})
}
