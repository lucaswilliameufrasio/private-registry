package repositories

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/workspaces"
)

// GrantPubReviewer grants review only, never read or publication. Human-facing
// callers must separately require recent MFA and CSRF.
func (s *Service) GrantPubReviewer(ctx context.Context, actor, workspace, repository, target string) (string, error) {
	actor, err := parseUUID(actor, ErrUnauthenticated)
	if err != nil {
		return "", ErrUnauthenticated
	}
	workspace, err = parseUUID(workspace, ErrInvalidWorkspaceID)
	if err != nil {
		return "", err
	}
	repository, err = parseUUID(repository, ErrInvalidRepositoryID)
	if err != nil {
		return "", err
	}
	target, err = parseUUID(target, ErrUserUnavailable)
	if err != nil || ctx == nil {
		return "", ErrUserUnavailable
	}
	var grantID string
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actor); err != nil {
			return err
		}
		role, err := activeWorkspaceRole(ctx, tx, s.driver, workspace, actor)
		if err != nil {
			return err
		}
		if role != workspaces.RoleOwner {
			return ErrForbidden
		}
		if err := RequireFormat(ctx, tx, s.driver, workspace, repository, FormatPub); err != nil {
			return err
		}
		if err := requireActiveUser(ctx, tx, s.driver, target); err != nil {
			return ErrUserUnavailable
		}
		if _, err := activeWorkspaceRole(ctx, tx, s.driver, workspace, target); err != nil {
			return ErrMembershipUnavailable
		}
		query := `SELECT grant_id FROM registry_pub_reviewer_grants WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND user_id = ` + bind(s.driver, 3) + ` AND revoked_at IS NULL`
		err = tx.QueryRowContext(ctx, query, workspace, repository, target).Scan(&grantID)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.New("pub reviewer grant could not be read")
		}
		id, err := uuid.NewV7()
		if err != nil {
			return errors.New("pub reviewer grant identity could not be created")
		}
		grantID = id.String()
		query = `INSERT INTO registry_pub_reviewer_grants (grant_id, workspace_id, repository_id, user_id, granted_by, granted_at) VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `, ` + bind(s.driver, 6) + `)`
		if _, err := tx.ExecContext(ctx, query, grantID, workspace, repository, target, actor, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return errors.New("pub reviewer grant could not be created")
		}
		return recordAudit(ctx, tx, s.driver, actor, "pub.reviewer.granted", "pub_reviewer_grant", grantID)
	})
	if err != nil {
		return "", err
	}
	return grantID, nil
}

func (s *Service) RevokePubReviewer(ctx context.Context, actor, workspace, repository, target string) error {
	actor, err := parseUUID(actor, ErrUnauthenticated)
	if err != nil {
		return ErrUnauthenticated
	}
	workspace, err = parseUUID(workspace, ErrInvalidWorkspaceID)
	if err != nil {
		return err
	}
	repository, err = parseUUID(repository, ErrInvalidRepositoryID)
	if err != nil {
		return err
	}
	target, err = parseUUID(target, ErrUserUnavailable)
	if err != nil || ctx == nil {
		return ErrUserUnavailable
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actor); err != nil {
			return err
		}
		role, err := activeWorkspaceRole(ctx, tx, s.driver, workspace, actor)
		if err != nil {
			return err
		}
		if role != workspaces.RoleOwner {
			return ErrForbidden
		}
		if err := RequireFormat(ctx, tx, s.driver, workspace, repository, FormatPub); err != nil {
			return err
		}
		query := `SELECT grant_id FROM registry_pub_reviewer_grants WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND user_id = ` + bind(s.driver, 3) + ` AND revoked_at IS NULL`
		var grantID string
		if err := tx.QueryRowContext(ctx, query, workspace, repository, target).Scan(&grantID); errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return errors.New("pub reviewer grant could not be read")
		}
		query = `UPDATE registry_pub_reviewer_grants SET revoked_at = ` + bind(s.driver, 1) + ` WHERE grant_id = ` + bind(s.driver, 2) + ` AND revoked_at IS NULL`
		if _, err := tx.ExecContext(ctx, query, time.Now().UTC().Format(time.RFC3339Nano), grantID); err != nil {
			return errors.New("pub reviewer grant could not be revoked")
		}
		return recordAudit(ctx, tx, s.driver, actor, "pub.reviewer.revoked", "pub_reviewer_grant", grantID)
	})
}

// WithPubReviewerTransaction rechecks the capability under the shared lock.
func (s *Service) WithPubReviewerTransaction(ctx context.Context, user, workspace, repository string, operation func(*sql.Tx, string) error) error {
	if s == nil || s.db == nil || ctx == nil || operation == nil {
		return errors.New("pub review transaction is unavailable")
	}
	user, err := parseUUID(user, ErrUnauthenticated)
	if err != nil {
		return ErrUnauthenticated
	}
	workspace, err = parseUUID(workspace, ErrInvalidWorkspaceID)
	if err != nil {
		return err
	}
	repository, err = parseUUID(repository, ErrInvalidRepositoryID)
	if err != nil {
		return err
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, user); err != nil {
			return err
		}
		if _, err := activeWorkspaceRole(ctx, tx, s.driver, workspace, user); err != nil {
			return err
		}
		if err := RequireFormat(ctx, tx, s.driver, workspace, repository, FormatPub); err != nil {
			return err
		}
		query := `SELECT grant_id FROM registry_pub_reviewer_grants WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND user_id = ` + bind(s.driver, 3) + ` AND revoked_at IS NULL`
		var grantID string
		if err := tx.QueryRowContext(ctx, query, workspace, repository, user).Scan(&grantID); errors.Is(err, sql.ErrNoRows) {
			return ErrForbidden
		} else if err != nil {
			return errors.New("pub reviewer capability could not be checked")
		}
		return operation(tx, grantID)
	})
}
