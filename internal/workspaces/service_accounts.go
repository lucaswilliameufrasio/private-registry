package workspaces

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrServiceAccountUnavailable = errors.New("service account is unavailable")
	ErrServiceAccountRole        = errors.New("service accounts can only be workspace members")
)

type ServiceAccount struct {
	UserID      string
	WorkspaceID string
	Description string
	Status      string
	CreatedBy   string
	CreatedAt   time.Time
}

// CreateServiceAccount adds an account that cannot sign in and belongs to one
// workspace as a member. It receives repository grants like any member and
// authenticates only with registry tokens issued by workspace managers.
func (s *Service) CreateServiceAccount(ctx context.Context, actorUserID, workspaceID, description string) (ServiceAccount, error) {
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return ServiceAccount{}, ErrUnauthenticated
	}
	workspaceID, err = parseWorkspaceID(workspaceID)
	if err != nil {
		return ServiceAccount{}, ErrInvalidWorkspaceID
	}
	description, err = normalizeDisplayName(description)
	if err != nil {
		return ServiceAccount{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return ServiceAccount{}, errors.New("service account identity could not be created")
	}
	now := time.Now().UTC()
	account := ServiceAccount{UserID: id.String(), WorkspaceID: workspaceID, Description: description, Status: "active", CreatedBy: actorID, CreatedAt: now.Truncate(time.Millisecond)}
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := s.requireManager(ctx, tx, workspaceID, actorID); err != nil {
			return err
		}
		stamp := now.Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (`+bind(s.driver, 1)+`, `+bind(s.driver, 2)+`, `+bind(s.driver, 3)+`, `+bind(s.driver, 4)+`)`, account.UserID, "service: "+description, stamp, stamp); err != nil {
			return errors.New("service account could not be created")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO registry_service_accounts (user_id, workspace_id, description, created_by, created_at_ms) VALUES (`+bind(s.driver, 1)+`, `+bind(s.driver, 2)+`, `+bind(s.driver, 3)+`, `+bind(s.driver, 4)+`, `+bind(s.driver, 5)+`)`, account.UserID, workspaceID, description, actorID, now.UnixMilli()); err != nil {
			return errors.New("service account could not be created")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, status, created_by, created_at, updated_at) VALUES (`+bind(s.driver, 1)+`, `+bind(s.driver, 2)+`, 'member', 'active', `+bind(s.driver, 3)+`, `+bind(s.driver, 4)+`, `+bind(s.driver, 5)+`)`, workspaceID, account.UserID, actorID, stamp, stamp); err != nil {
			return errors.New("service account membership could not be created")
		}
		return recordAudit(ctx, tx, s.driver, actorID, "service_account.created", "user", account.UserID)
	})
	if err != nil {
		return ServiceAccount{}, err
	}
	return account, nil
}

func (s *Service) requireManager(ctx context.Context, tx *sql.Tx, workspaceID, actorID string) error {
	if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
		return err
	}
	role, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID)
	if err != nil {
		return err
	}
	if role != RoleOwner && role != RoleAdministrator {
		return ErrForbidden
	}
	return nil
}

// ListServiceAccounts is for workspace managers.
func (s *Service) ListServiceAccounts(ctx context.Context, actorUserID, workspaceID string) ([]ServiceAccount, error) {
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	workspaceID, err = parseWorkspaceID(workspaceID)
	if err != nil {
		return nil, ErrInvalidWorkspaceID
	}
	var accounts []ServiceAccount
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := s.requireManager(ctx, tx, workspaceID, actorID); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT a.user_id, a.description, u.status, a.created_by, a.created_at_ms FROM registry_service_accounts a JOIN registry_users u ON u.user_id = a.user_id WHERE a.workspace_id = `+bind(s.driver, 1)+` ORDER BY a.user_id LIMIT 500`, workspaceID)
		if err != nil {
			return errors.New("service accounts could not be listed")
		}
		defer rows.Close()
		for rows.Next() {
			account := ServiceAccount{WorkspaceID: workspaceID}
			var created int64
			if err := rows.Scan(&account.UserID, &account.Description, &account.Status, &account.CreatedBy, &created); err != nil {
				return errors.New("service account could not be read")
			}
			account.CreatedAt = time.UnixMilli(created).UTC()
			accounts = append(accounts, account)
		}
		return rows.Err()
	})
	return accounts, err
}

// DisableServiceAccount suspends the account, which revokes its tokens and
// stops trusted publishing for it. It cannot be re-enabled: create a new one.
func (s *Service) DisableServiceAccount(ctx context.Context, actorUserID, workspaceID, accountID string) error {
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return ErrUnauthenticated
	}
	workspaceID, err = parseWorkspaceID(workspaceID)
	if err != nil {
		return ErrInvalidWorkspaceID
	}
	accountID, err = parseUserID(accountID)
	if err != nil {
		return ErrServiceAccountUnavailable
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := s.requireManager(ctx, tx, workspaceID, actorID); err != nil {
			return err
		}
		if err := s.requireServiceAccount(ctx, tx, workspaceID, accountID); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE registry_users SET status = 'suspended', updated_at = `+bind(s.driver, 1)+` WHERE user_id = `+bind(s.driver, 2)+` AND status = 'active'`, time.Now().UTC().Format(time.RFC3339Nano), accountID)
		if err != nil {
			return errors.New("service account could not be disabled")
		}
		if changed, _ := result.RowsAffected(); changed == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE registry_trusted_publishers SET revoked_at_ms = `+bind(s.driver, 1)+` WHERE service_account_id = `+bind(s.driver, 2)+` AND revoked_at_ms IS NULL`, time.Now().UTC().UnixMilli(), accountID); err != nil {
			return errors.New("trusted publishers could not be revoked")
		}
		return recordAudit(ctx, tx, s.driver, actorID, "service_account.disabled", "user", accountID)
	})
}

// RequireServiceAccountManager checks, in its own transaction, that actor
// manages the workspace and that account is an active service account of it.
// Callers then act on behalf of the account.
func (s *Service) RequireServiceAccountManager(ctx context.Context, actorUserID, workspaceID, accountID string) error {
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return ErrUnauthenticated
	}
	workspaceID, err = parseWorkspaceID(workspaceID)
	if err != nil {
		return ErrInvalidWorkspaceID
	}
	accountID, err = parseUserID(accountID)
	if err != nil {
		return ErrServiceAccountUnavailable
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := s.requireManager(ctx, tx, workspaceID, actorID); err != nil {
			return err
		}
		if err := s.requireServiceAccount(ctx, tx, workspaceID, accountID); err != nil {
			return err
		}
		return requireActiveUser(ctx, tx, s.driver, accountID)
	})
}

func (s *Service) requireServiceAccount(ctx context.Context, tx *sql.Tx, workspaceID, accountID string) error {
	var found bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_service_accounts WHERE user_id = `+bind(s.driver, 1)+` AND workspace_id = `+bind(s.driver, 2)+`)`, accountID, workspaceID).Scan(&found); err != nil {
		return errors.New("service account could not be checked")
	}
	if !found {
		return ErrServiceAccountUnavailable
	}
	return nil
}

func isServiceAccount(ctx context.Context, tx *sql.Tx, s *Service, userID string) (bool, error) {
	var found bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_service_accounts WHERE user_id = `+bind(s.driver, 1)+`)`, userID).Scan(&found)
	return found, err
}

// Member is one active membership as seen by other members.
type Member struct {
	UserID         string
	DisplayName    string
	LoginName      string
	Role           string
	ServiceAccount bool
}

// ListMembers returns the active members of a workspace to any active member,
// so people can find whom to grant access to. Contact emails are not shown.
func (s *Service) ListMembers(ctx context.Context, actorUserID, workspaceID string) ([]Member, error) {
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	workspaceID, err = parseWorkspaceID(workspaceID)
	if err != nil {
		return nil, ErrInvalidWorkspaceID
	}
	var members []Member
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		if _, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT m.user_id, u.display_name, COALESCE(c.login_name, ''), m.role, EXISTS (SELECT 1 FROM registry_service_accounts a WHERE a.user_id = m.user_id) FROM registry_workspace_memberships m JOIN registry_users u ON u.user_id = m.user_id LEFT JOIN registry_local_credentials c ON c.user_id = m.user_id WHERE m.workspace_id = `+bind(s.driver, 1)+` AND m.status = 'active' AND u.status = 'active' ORDER BY u.display_name, m.user_id LIMIT 1000`, workspaceID)
		if err != nil {
			return errors.New("workspace members could not be listed")
		}
		defer rows.Close()
		for rows.Next() {
			var member Member
			if err := rows.Scan(&member.UserID, &member.DisplayName, &member.LoginName, &member.Role, &member.ServiceAccount); err != nil {
				return errors.New("workspace member could not be read")
			}
			members = append(members, member)
		}
		return rows.Err()
	})
	return members, err
}

// Profile is what a signed-in person sees about their own account.
type Profile struct {
	UserID        string
	DisplayName   string
	LoginName     string
	InstanceAdmin bool
	HasTOTP       bool
	Passkeys      int
}

func (s *Service) Profile(ctx context.Context, userID string) (Profile, error) {
	id, err := parseUserID(userID)
	if err != nil {
		return Profile{}, ErrUnauthenticated
	}
	profile := Profile{UserID: id}
	err = s.db.QueryRowContext(ctx, `SELECT u.display_name, COALESCE(c.login_name, ''), EXISTS (SELECT 1 FROM registry_instance_admins a WHERE a.user_id = u.user_id), EXISTS (SELECT 1 FROM registry_totp_credentials t WHERE t.user_id = u.user_id AND t.status = 'active'), (SELECT COUNT(*) FROM registry_webauthn_credentials w WHERE w.user_id = u.user_id) FROM registry_users u LEFT JOIN registry_local_credentials c ON c.user_id = u.user_id WHERE u.user_id = `+bind(s.driver, 1)+` AND u.status = 'active'`, id).Scan(&profile.DisplayName, &profile.LoginName, &profile.InstanceAdmin, &profile.HasTOTP, &profile.Passkeys)
	if err != nil {
		return Profile{}, ErrUserUnavailable
	}
	return profile, nil
}
