package repositories

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/workspaces"
)

type GrantRole string

const (
	GrantReader     GrantRole = "reader"
	GrantPublisher  GrantRole = "publisher"
	GrantMaintainer GrantRole = "maintainer"
	GrantSecurity   GrantRole = "security"
)

var (
	ErrInvalidGrantRole      = errors.New("repository grant role is invalid")
	ErrInvalidGrantCursor    = errors.New("repository grant cursor is invalid")
	ErrInvalidGrantPageSize  = errors.New("repository grant page size is invalid")
	ErrMembershipUnavailable = errors.New("active workspace membership is required")
)

type RepositoryGrant struct {
	ID           string
	RepositoryID string
	WorkspaceID  string
	UserID       string
	Role         GrantRole
	GrantedBy    string
	GrantedAt    time.Time
}

// GrantRepositoryRole creates an explicit role grant for an active workspace
// member. Repeating an active grant is idempotent and does not create another
// audit event.
func (s *Service) GrantRepositoryRole(
	ctx context.Context,
	actorUserID string,
	workspaceID string,
	repositoryID string,
	targetUserID string,
	role GrantRole,
) (RepositoryGrant, error) {
	if ctx == nil {
		return RepositoryGrant{}, errors.New("repository grant context is required")
	}
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return RepositoryGrant{}, ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return RepositoryGrant{}, ErrInvalidWorkspaceID
	}
	repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
	if err != nil {
		return RepositoryGrant{}, ErrInvalidRepositoryID
	}
	targetID, err := parseUUID(targetUserID, ErrUserUnavailable)
	if err != nil {
		return RepositoryGrant{}, ErrUserUnavailable
	}
	if !validGrantRole(role) {
		return RepositoryGrant{}, ErrInvalidGrantRole
	}

	var grant RepositoryGrant
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		actorRole, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID)
		if err != nil {
			return err
		}
		if actorRole != workspaces.RoleOwner && actorRole != workspaces.RoleAdministrator {
			return ErrForbidden
		}
		if actorRole == workspaces.RoleAdministrator {
			if role != GrantReader && role != GrantPublisher {
				return ErrForbidden
			}
			if actorID == targetID {
				return ErrForbidden
			}
		}
		if err := requireActiveRepository(ctx, tx, s.driver, workspaceID, repositoryID); err != nil {
			return err
		}
		if err := requireActiveUser(ctx, tx, s.driver, targetID); err != nil {
			return ErrUserUnavailable
		}
		if _, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, targetID); err != nil {
			if errors.Is(err, ErrForbidden) {
				return ErrMembershipUnavailable
			}
			return err
		}

		query := `SELECT grant_id, granted_by, granted_at
			FROM registry_repository_grants
			WHERE workspace_id = ` + bind(s.driver, 1) + `
				AND repository_id = ` + bind(s.driver, 2) + `
				AND user_id = ` + bind(s.driver, 3) + `
				AND role = ` + bind(s.driver, 4) + ` AND revoked_at IS NULL`
		var grantID string
		var grantedBy string
		var grantedAt string
		err = tx.QueryRowContext(ctx, query, workspaceID, repositoryID, targetID, string(role)).Scan(
			&grantID, &grantedBy, &grantedAt)
		if err == nil {
			grant, err = parseRepositoryGrant(grantID, repositoryID, workspaceID, targetID, role, grantedBy, grantedAt)
			if err != nil {
				return errors.New("stored repository grant is invalid")
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.New("existing repository grant could not be read")
		}

		newGrantID, err := uuid.NewV7()
		if err != nil {
			return errors.New("repository grant identity could not be generated")
		}
		now := time.Now().UTC()
		grantedAt = now.Format(time.RFC3339Nano)
		query = `INSERT INTO registry_repository_grants
			(grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at)
			VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `, ` + bind(s.driver, 6) + `, ` + bind(s.driver, 7) + `)`
		if _, err := tx.ExecContext(ctx, query,
			newGrantID.String(), repositoryID, workspaceID, targetID, string(role), actorID, grantedAt); err != nil {
			return errors.New("repository grant could not be created")
		}
		if err := recordAudit(ctx, tx, s.driver, actorID,
			"repository.grant.created", "repository_grant", newGrantID.String()); err != nil {
			return err
		}
		grant = RepositoryGrant{
			ID:           newGrantID.String(),
			RepositoryID: repositoryID,
			WorkspaceID:  workspaceID,
			UserID:       targetID,
			Role:         role,
			GrantedBy:    actorID,
			GrantedAt:    now,
		}
		return nil
	})
	if err != nil {
		return RepositoryGrant{}, err
	}
	return grant, nil
}

// RevokeRepositoryRole revokes an active grant. Repeating the revocation is
// idempotent. An administrator may revoke only reader and publisher grants;
// owners may revoke any role.
func (s *Service) RevokeRepositoryRole(
	ctx context.Context,
	actorUserID string,
	workspaceID string,
	repositoryID string,
	targetUserID string,
	role GrantRole,
) error {
	if ctx == nil {
		return errors.New("repository grant revocation context is required")
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
	targetID, err := parseUUID(targetUserID, ErrUserUnavailable)
	if err != nil {
		return ErrUserUnavailable
	}
	if !validGrantRole(role) {
		return ErrInvalidGrantRole
	}

	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		actorRole, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID)
		if err != nil {
			return err
		}
		if actorRole != workspaces.RoleOwner && actorRole != workspaces.RoleAdministrator {
			return ErrForbidden
		}
		if actorRole == workspaces.RoleAdministrator && role != GrantReader && role != GrantPublisher {
			return ErrForbidden
		}
		if err := requireActiveRepository(ctx, tx, s.driver, workspaceID, repositoryID); err != nil {
			return err
		}

		query := `SELECT grant_id FROM registry_repository_grants
			WHERE workspace_id = ` + bind(s.driver, 1) + `
				AND repository_id = ` + bind(s.driver, 2) + `
				AND user_id = ` + bind(s.driver, 3) + `
				AND role = ` + bind(s.driver, 4) + ` AND revoked_at IS NULL`
		var grantID string
		err = tx.QueryRowContext(ctx, query, workspaceID, repositoryID, targetID, string(role)).Scan(&grantID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return errors.New("active repository grant could not be read")
		}

		now := time.Now().UTC().Format(time.RFC3339Nano)
		query = `UPDATE registry_repository_grants
			SET revoked_at = ` + bind(s.driver, 1) + `, revoked_by = ` + bind(s.driver, 2) + `,
				revocation_reason = 'manual'
			WHERE grant_id = ` + bind(s.driver, 3) + ` AND revoked_at IS NULL`
		result, err := tx.ExecContext(ctx, query, now, actorID, grantID)
		if err != nil {
			return errors.New("repository grant could not be revoked")
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil || rowsAffected != 1 {
			return errors.New("repository grant revocation result could not be checked")
		}
		return recordAudit(ctx, tx, s.driver, actorID,
			"repository.grant.revoked", "repository_grant", grantID)
	})
}

// ListRepositoryGrants returns active grants for workspace owners and
// administrators. The cursor is an immutable grant UUID to keep pagination
// stable while grants are added or revoked.
func (s *Service) ListRepositoryGrants(
	ctx context.Context,
	actorUserID string,
	workspaceID string,
	repositoryID string,
	afterGrantID string,
	pageSize int,
) ([]RepositoryGrant, bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, false, errors.New("repository grant list service is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return nil, false, ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return nil, false, ErrInvalidWorkspaceID
	}
	repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
	if err != nil {
		return nil, false, ErrInvalidRepositoryID
	}
	if afterGrantID != "" {
		afterGrantID, err = parseUUID(afterGrantID, ErrInvalidGrantCursor)
		if err != nil {
			return nil, false, ErrInvalidGrantCursor
		}
	}
	if pageSize < 1 || pageSize > maxRepositoryPageSize {
		return nil, false, ErrInvalidGrantPageSize
	}
	if err := requireActiveUserDB(ctx, s.db, s.driver, actorID); err != nil {
		return nil, false, err
	}
	actorRole, err := activeWorkspaceRoleDB(ctx, s.db, s.driver, workspaceID, actorID)
	if err != nil {
		return nil, false, err
	}
	if actorRole != workspaces.RoleOwner && actorRole != workspaces.RoleAdministrator {
		return nil, false, ErrForbidden
	}
	if err := requireActiveRepositoryDB(ctx, s.db, s.driver, workspaceID, repositoryID); err != nil {
		return nil, false, err
	}

	query := `WITH actor_authority AS (
		SELECT 1
		FROM registry_workspace_memberships AS actor_memberships
		JOIN registry_users AS actor_users ON actor_users.user_id = actor_memberships.user_id
		JOIN registry_workspaces AS actor_workspaces ON actor_workspaces.workspace_id = actor_memberships.workspace_id
		WHERE actor_memberships.workspace_id = ` + bind(s.driver, 1) + `
			AND actor_memberships.user_id = ` + bind(s.driver, 2) + `
			AND actor_memberships.status = 'active'
			AND actor_workspaces.status = 'active' AND actor_users.status = 'active'
			AND actor_memberships.role IN ('owner', 'administrator')
	)
	SELECT grants.grant_id, grants.repository_id, grants.workspace_id,
		grants.user_id, grants.role, grants.granted_by, grants.granted_at
		FROM registry_repository_grants AS grants
		JOIN registry_repositories AS repositories
			ON repositories.repository_id = grants.repository_id
			AND repositories.workspace_id = grants.workspace_id
		JOIN registry_workspace_memberships AS memberships
			ON memberships.workspace_id = grants.workspace_id AND memberships.user_id = grants.user_id
		JOIN registry_workspaces AS workspaces ON workspaces.workspace_id = grants.workspace_id
		JOIN registry_users AS users ON users.user_id = grants.user_id
		WHERE grants.workspace_id = ` + bind(s.driver, 3) + `
			AND grants.repository_id = ` + bind(s.driver, 4) + `
			AND grants.revoked_at IS NULL
			AND repositories.status = 'active'
			AND memberships.status = 'active' AND workspaces.status = 'active' AND users.status = 'active'
			AND EXISTS (SELECT 1 FROM actor_authority)`
	args := []any{workspaceID, actorID, workspaceID, repositoryID}
	if afterGrantID != "" {
		query += " AND grants.grant_id > " + bind(s.driver, 5)
		args = append(args, afterGrantID)
	}
	query += " ORDER BY grants.grant_id ASC LIMIT " + bind(s.driver, len(args)+1)
	args = append(args, pageSize+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, errors.New("repository grants could not be read")
	}
	defer rows.Close()

	grants := make([]RepositoryGrant, 0, pageSize+1)
	for rows.Next() {
		var grant RepositoryGrant
		var role string
		var grantedAt string
		if err := rows.Scan(&grant.ID, &grant.RepositoryID, &grant.WorkspaceID,
			&grant.UserID, &role, &grant.GrantedBy, &grantedAt); err != nil {
			return nil, false, errors.New("repository grant record is invalid")
		}
		parsedGrant, err := parseRepositoryGrant(
			grant.ID, grant.RepositoryID, grant.WorkspaceID, grant.UserID,
			GrantRole(role), grant.GrantedBy, grantedAt)
		if err != nil {
			return nil, false, errors.New("repository grant record is invalid")
		}
		grants = append(grants, parsedGrant)
	}
	if err := rows.Err(); err != nil {
		return nil, false, errors.New("repository grants could not be read")
	}
	if len(grants) <= pageSize {
		return grants, false, nil
	}
	return grants[:pageSize], true, nil
}

// HasRepositoryGrant revalidates the user's active membership and the current
// grant on every call. It does not infer grants from owner, administrator, or
// installation-administrator status.
func (s *Service) HasRepositoryGrant(
	ctx context.Context,
	userID string,
	workspaceID string,
	repositoryID string,
	role GrantRole,
) (bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return false, errors.New("repository grant authorization service is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	userID, err := parseUUID(userID, ErrUnauthenticated)
	if err != nil {
		return false, ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return false, ErrInvalidWorkspaceID
	}
	repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
	if err != nil {
		return false, ErrInvalidRepositoryID
	}
	if !validGrantRole(role) {
		return false, ErrInvalidGrantRole
	}
	if err := requireActiveUserDB(ctx, s.db, s.driver, userID); err != nil {
		return false, err
	}
	if _, err := activeWorkspaceRoleDB(ctx, s.db, s.driver, workspaceID, userID); err != nil {
		return false, err
	}

	query := `SELECT EXISTS (
		SELECT 1
		FROM registry_repository_grants AS grants
		JOIN registry_repositories AS repositories
			ON repositories.repository_id = grants.repository_id
			AND repositories.workspace_id = grants.workspace_id
		JOIN registry_workspace_memberships AS memberships
			ON memberships.workspace_id = grants.workspace_id AND memberships.user_id = grants.user_id
		JOIN registry_workspaces AS workspaces ON workspaces.workspace_id = grants.workspace_id
		JOIN registry_users AS users ON users.user_id = grants.user_id
		WHERE grants.user_id = ` + bind(s.driver, 1) + `
			AND grants.workspace_id = ` + bind(s.driver, 2) + `
			AND grants.repository_id = ` + bind(s.driver, 3) + `
			AND grants.role = ` + bind(s.driver, 4) + `
			AND grants.revoked_at IS NULL
			AND repositories.status = 'active'
			AND memberships.status = 'active'
			AND workspaces.status = 'active'
			AND users.status = 'active'
	)`
	var found bool
	if err := s.db.QueryRowContext(ctx, query, userID, workspaceID, repositoryID, string(role)).Scan(&found); err != nil {
		return false, errors.New("repository grant authorization could not be checked")
	}
	return found, nil
}

func requireActiveRepository(
	ctx context.Context,
	tx *sql.Tx,
	driver config.DatabaseDriver,
	workspaceID string,
	repositoryID string,
) error {
	var active bool
	query := `SELECT EXISTS (
		SELECT 1 FROM registry_repositories
		WHERE workspace_id = ` + bind(driver, 1) + `
			AND repository_id = ` + bind(driver, 2) + ` AND status = 'active'
	)`
	if err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&active); err != nil {
		return errors.New("repository availability could not be checked")
	}
	if !active {
		return ErrRepositoryUnavailable
	}
	return nil
}

func requireActiveRepositoryDB(
	ctx context.Context,
	db *sql.DB,
	driver config.DatabaseDriver,
	workspaceID string,
	repositoryID string,
) error {
	var active bool
	query := `SELECT EXISTS (
		SELECT 1 FROM registry_repositories
		WHERE workspace_id = ` + bind(driver, 1) + `
			AND repository_id = ` + bind(driver, 2) + ` AND status = 'active'
	)`
	if err := db.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&active); err != nil {
		return errors.New("repository availability could not be checked")
	}
	if !active {
		return ErrRepositoryUnavailable
	}
	return nil
}

func parseRepositoryGrant(
	grantID string,
	repositoryID string,
	workspaceID string,
	userID string,
	role GrantRole,
	grantedBy string,
	grantedAt string,
) (RepositoryGrant, error) {
	grantID, err := parseUUID(grantID, ErrInvalidGrantCursor)
	if err != nil {
		return RepositoryGrant{}, err
	}
	repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
	if err != nil {
		return RepositoryGrant{}, err
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return RepositoryGrant{}, err
	}
	userID, err = parseUUID(userID, ErrUserUnavailable)
	if err != nil {
		return RepositoryGrant{}, err
	}
	grantedBy, err = parseUUID(grantedBy, ErrUnauthenticated)
	if err != nil {
		return RepositoryGrant{}, err
	}
	if !validGrantRole(role) {
		return RepositoryGrant{}, ErrInvalidGrantRole
	}
	parsedAt, err := time.Parse(time.RFC3339Nano, grantedAt)
	if err != nil {
		return RepositoryGrant{}, err
	}
	return RepositoryGrant{
		ID:           grantID,
		RepositoryID: repositoryID,
		WorkspaceID:  workspaceID,
		UserID:       userID,
		Role:         role,
		GrantedBy:    grantedBy,
		GrantedAt:    parsedAt.UTC(),
	}, nil
}

func validGrantRole(role GrantRole) bool {
	switch role {
	case GrantReader, GrantPublisher, GrantMaintainer, GrantSecurity:
		return true
	default:
		return false
	}
}
