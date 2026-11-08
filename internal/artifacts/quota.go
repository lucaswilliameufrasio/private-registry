package artifacts

import (
	"context"
	"database/sql"
	"errors"
)

// checkGenericQuota runs under the repository write transaction's shared
// installation lock. Upload-session insertion is the reservation; rejected or
// expired sessions release it, while uploaded and published sessions retain it.
// Other artifact formats and administrator-managed policy are not yet covered.
func (s *Service) checkGenericQuota(ctx context.Context, tx *sql.Tx, workspaceID, repositoryID string, size int64) error {
	if size == 0 {
		return nil
	}
	var workspaceLimit, repositoryLimit sql.NullInt64
	query := `SELECT w.logical_quota_bytes, r.logical_quota_bytes
		FROM registry_workspaces w JOIN registry_repositories r ON r.workspace_id = w.workspace_id
		WHERE w.workspace_id = ` + bind(s.driver, 1) + ` AND r.repository_id = ` + bind(s.driver, 2)
	if err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&workspaceLimit, &repositoryLimit); err != nil {
		return errors.New("artifact quota policy could not be read")
	}
	// Each published Go version owns its ZIP and separately served go.mod.
	// Count both logical references, even when physical objects are shared.
	var goUsage, goReserved int64
	if workspaceLimit.Valid {
		query = `SELECT COALESCE(SUM(zip_size + LENGTH(mod_bytes)), 0) FROM registry_go_module_versions WHERE workspace_id = ` + bind(s.driver, 1)
		if err := tx.QueryRowContext(ctx, query, workspaceID).Scan(&goUsage); err != nil || goUsage < 0 {
			return errors.New("workspace quota accounting could not be checked")
		}
		query = `SELECT COALESCE(SUM(zip_size + LENGTH(mod_bytes)), 0) FROM registry_go_upload_sessions WHERE workspace_id = ` + bind(s.driver, 1) + ` AND status IN ('receiving', 'uploading', 'uploaded')`
		if err := tx.QueryRowContext(ctx, query, workspaceID).Scan(&goReserved); err != nil || goReserved < 0 {
			return errors.New("workspace quota reservations could not be checked")
		}
	}
	for _, limit := range []struct {
		value      sql.NullInt64
		repository bool
	}{{workspaceLimit, false}, {repositoryLimit, true}} {
		if !limit.value.Valid {
			continue
		}
		if size > limit.value.Int64 {
			return ErrLogicalQuotaExceeded
		}
		query = `SELECT COALESCE(SUM(expected_size), 0) FROM registry_generic_upload_sessions
			WHERE workspace_id = ` + bind(s.driver, 1) + ` AND status IN ('receiving', 'uploading', 'uploaded', 'published')`
		args := []any{workspaceID}
		if limit.repository {
			query += ` AND repository_id = ` + bind(s.driver, 2)
			args = append(args, repositoryID)
		}
		var used int64
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&used); err != nil || used < 0 {
			return errors.New("artifact quota usage could not be read")
		}
		if used > limit.value.Int64-size {
			return ErrLogicalQuotaExceeded
		}
		if !limit.repository && goUsage > limit.value.Int64-size-used {
			return ErrLogicalQuotaExceeded
		}
		if !limit.repository && goReserved > limit.value.Int64-size-used-goUsage {
			return ErrLogicalQuotaExceeded
		}
	}
	return nil
}
