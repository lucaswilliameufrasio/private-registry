package repositories

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/workspaces"
)

// GrantGoReviewer gives an explicit review capability to an active workspace
// member. Owners alone may manage this capability; it grants no package access.
func (s *Service) GrantGoReviewer(ctx context.Context, actorUserID, workspaceID, repositoryID, targetUserID string) (string, error) {
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return "", ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return "", ErrInvalidWorkspaceID
	}
	repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
	if err != nil {
		return "", ErrInvalidRepositoryID
	}
	targetID, err := parseUUID(targetUserID, ErrUserUnavailable)
	if err != nil {
		return "", ErrUserUnavailable
	}
	var grantID string
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		role, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID)
		if err != nil {
			return err
		}
		if role != workspaces.RoleOwner {
			return ErrForbidden
		}
		if err := RequireFormat(ctx, tx, s.driver, workspaceID, repositoryID, FormatGo); err != nil {
			return err
		}
		if err := requireActiveUser(ctx, tx, s.driver, targetID); err != nil {
			return ErrUserUnavailable
		}
		if _, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, targetID); err != nil {
			return ErrMembershipUnavailable
		}
		query := `SELECT grant_id FROM registry_go_reviewer_grants WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND user_id = ` + bind(s.driver, 3) + ` AND revoked_at IS NULL`
		err = tx.QueryRowContext(ctx, query, workspaceID, repositoryID, targetID).Scan(&grantID)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.New("Go reviewer grant could not be read")
		}
		id, err := uuid.NewV7()
		if err != nil {
			return errors.New("Go reviewer grant identity could not be created")
		}
		grantID = id.String()
		query = `INSERT INTO registry_go_reviewer_grants (grant_id, workspace_id, repository_id, user_id, granted_by, granted_at) VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `, ` + bind(s.driver, 6) + `)`
		if _, err := tx.ExecContext(ctx, query, grantID, workspaceID, repositoryID, targetID, actorID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return errors.New("Go reviewer grant could not be created")
		}
		return recordAudit(ctx, tx, s.driver, actorID, "go.reviewer.granted", "go_reviewer_grant", grantID)
	})
	if err != nil {
		return "", err
	}
	return grantID, nil
}

// RevokeGoReviewer invalidates approvals bound to the current grant, including
// after the member is granted a new capability.
func (s *Service) RevokeGoReviewer(ctx context.Context, actorUserID, workspaceID, repositoryID, targetUserID string) error {
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
	targetID, err := parseUUID(targetUserID, ErrUserUnavailable)
	if err != nil {
		return ErrUserUnavailable
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		role, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID)
		if err != nil {
			return err
		}
		if role != workspaces.RoleOwner {
			return ErrForbidden
		}
		if err := requireActiveRepository(ctx, tx, s.driver, workspaceID, repositoryID); err != nil {
			return err
		}
		query := `SELECT grant_id FROM registry_go_reviewer_grants WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND user_id = ` + bind(s.driver, 3) + ` AND revoked_at IS NULL`
		var grantID string
		if err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID, targetID).Scan(&grantID); errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return errors.New("Go reviewer grant could not be read")
		}
		query = `UPDATE registry_go_reviewer_grants SET revoked_at = ` + bind(s.driver, 1) + ` WHERE grant_id = ` + bind(s.driver, 2) + ` AND revoked_at IS NULL`
		if _, err := tx.ExecContext(ctx, query, time.Now().UTC().Format(time.RFC3339Nano), grantID); err != nil {
			return errors.New("Go reviewer grant could not be revoked")
		}
		return recordAudit(ctx, tx, s.driver, actorID, "go.reviewer.revoked", "go_reviewer_grant", grantID)
	})
}

// WithGoReviewerTransaction rechecks the current reviewer grant under the same
// lock used for membership, grant, review policy, and publication changes.
func (s *Service) WithGoReviewerTransaction(ctx context.Context, userID, workspaceID, repositoryID string, operation func(*sql.Tx, string) error) error {
	if ctx == nil || operation == nil {
		return errors.New("Go review transaction is unavailable")
	}
	userID, err := parseUUID(userID, ErrUnauthenticated)
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
		if err := requireActiveUser(ctx, tx, s.driver, userID); err != nil {
			return err
		}
		if _, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, userID); err != nil {
			return err
		}
		if err := requireActiveRepository(ctx, tx, s.driver, workspaceID, repositoryID); err != nil {
			return err
		}
		query := `SELECT grant_id FROM registry_go_reviewer_grants WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND user_id = ` + bind(s.driver, 3) + ` AND revoked_at IS NULL`
		var grantID string
		if err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID, userID).Scan(&grantID); errors.Is(err, sql.ErrNoRows) {
			return ErrForbidden
		} else if err != nil {
			return errors.New("Go reviewer capability could not be checked")
		}
		if err := RequireFormat(ctx, tx, s.driver, workspaceID, repositoryID, FormatGo); err != nil {
			return err
		}
		return operation(tx, grantID)
	})
}
