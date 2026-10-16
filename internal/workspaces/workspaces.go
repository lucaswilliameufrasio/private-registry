package workspaces

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"private-registry/internal/config"
)

type CreationPolicy string

const (
	CreationAdminOnly       CreationPolicy = "admin_only"
	CreationAuthorizedUsers CreationPolicy = "authorized_users"
	CreationAnyUser         CreationPolicy = "any_user"
)

var (
	ErrUnauthenticated = errors.New("authenticated user is required")
	ErrForbidden       = errors.New("operation is not permitted")
	ErrInvalidSlug     = errors.New("workspace slug is invalid")
	ErrInvalidName     = errors.New("workspace display name is invalid")
	ErrInvalidPolicy   = errors.New("workspace creation policy is invalid")
	ErrSlugConflict    = errors.New("workspace slug is already reserved")
	ErrUserUnavailable = errors.New("user is unavailable")

	workspaceSlugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

type Workspace struct {
	ID          string
	Slug        string
	DisplayName string
	Status      string
	CreatedBy   string
	CreatedAt   time.Time
}

type Service struct {
	db     *sql.DB
	driver config.DatabaseDriver
}

func New(db *sql.DB, driver config.DatabaseDriver) (*Service, error) {
	if db == nil {
		return nil, errors.New("workspace database is required")
	}
	if driver != config.SQLite && driver != config.Postgres {
		return nil, errors.New("workspace database driver must be sqlite or postgres")
	}
	return &Service{db: db, driver: driver}, nil
}

// SetCreationPolicy changes who may create workspaces. actorUserID must come
// from a verified server-side principal; it must never be copied from a request
// body, query parameter, or untrusted header.
func (s *Service) SetCreationPolicy(
	ctx context.Context,
	actorUserID string,
	policy CreationPolicy,
) error {
	if ctx == nil {
		return errors.New("workspace policy context is required")
	}
	if !validPolicy(policy) {
		return ErrInvalidPolicy
	}
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return ErrUnauthenticated
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		isAdministrator, err := isInstanceAdministrator(ctx, tx, s.driver, actorID)
		if err != nil {
			return errors.New("administrator authorization could not be checked")
		}
		if !isAdministrator {
			return ErrForbidden
		}

		currentPolicy, err := readCreationPolicy(ctx, tx, s.driver)
		if err != nil {
			return errors.New("workspace creation policy could not be read")
		}
		if currentPolicy == policy {
			return nil
		}
		query := "UPDATE registry_installation SET workspace_creation_policy = " + bind(s.driver, 1) + " WHERE singleton_id = 1"
		if _, err := tx.ExecContext(ctx, query, string(policy)); err != nil {
			return errors.New("workspace creation policy could not be updated")
		}
		return recordAudit(ctx, tx, s.driver, actorID, "workspace_creation_policy.changed", "installation", "1")
	})
}

// GrantWorkspaceCreation adds or renews an explicit workspace-creation grant.
// actorUserID must come from a verified server-side principal.
func (s *Service) GrantWorkspaceCreation(
	ctx context.Context,
	actorUserID string,
	targetUserID string,
) error {
	if ctx == nil {
		return errors.New("workspace grant context is required")
	}
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return ErrUnauthenticated
	}
	targetID, err := parseUserID(targetUserID)
	if err != nil {
		return ErrUserUnavailable
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveAdministrator(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		if err := requireActiveUser(ctx, tx, s.driver, targetID); err != nil {
			return ErrUserUnavailable
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		query := `INSERT INTO registry_workspace_creation_grants (user_id, granted_by, granted_at, revoked_at)
			VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, NULL)
			ON CONFLICT (user_id) DO UPDATE SET granted_by = excluded.granted_by, granted_at = excluded.granted_at, revoked_at = NULL`
		if _, err := tx.ExecContext(ctx, query, targetID, actorID, now); err != nil {
			return errors.New("workspace creation grant could not be recorded")
		}
		return recordAudit(ctx, tx, s.driver, actorID, "workspace_creation_grant.granted", "user", targetID)
	})
}

// RevokeWorkspaceCreation removes an explicit workspace-creation grant.
// actorUserID must come from a verified server-side principal.
func (s *Service) RevokeWorkspaceCreation(
	ctx context.Context,
	actorUserID string,
	targetUserID string,
) error {
	if ctx == nil {
		return errors.New("workspace grant context is required")
	}
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return ErrUnauthenticated
	}
	targetID, err := parseUserID(targetUserID)
	if err != nil {
		return ErrUserUnavailable
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveAdministrator(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		query := "UPDATE registry_workspace_creation_grants SET revoked_at = " + bind(s.driver, 1) +
			" WHERE user_id = " + bind(s.driver, 2) + " AND revoked_at IS NULL"
		result, err := tx.ExecContext(ctx, query, time.Now().UTC().Format(time.RFC3339Nano), targetID)
		if err != nil {
			return errors.New("workspace creation grant could not be revoked")
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return errors.New("workspace creation grant result could not be checked")
		}
		if rowsAffected == 0 {
			return nil
		}
		return recordAudit(ctx, tx, s.driver, actorID, "workspace_creation_grant.revoked", "user", targetID)
	})
}

// CreateWorkspace creates a private tenancy boundary and makes the verified
// caller its first owner. Membership does not imply package publication.
func (s *Service) CreateWorkspace(
	ctx context.Context,
	actorUserID string,
	slug string,
	displayName string,
) (workspace Workspace, retErr error) {
	if ctx == nil {
		return Workspace{}, errors.New("workspace creation context is required")
	}
	actorID, err := parseUserID(actorUserID)
	if err != nil {
		return Workspace{}, ErrUnauthenticated
	}
	slug = strings.TrimSpace(slug)
	if !workspaceSlugPattern.MatchString(slug) {
		return Workspace{}, ErrInvalidSlug
	}
	displayName, err = normalizeDisplayName(displayName)
	if err != nil {
		return Workspace{}, err
	}

	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		isAdministrator, err := isInstanceAdministrator(ctx, tx, s.driver, actorID)
		if err != nil {
			return errors.New("workspace creation authority could not be checked")
		}
		policy, err := readCreationPolicy(ctx, tx, s.driver)
		if err != nil {
			return errors.New("workspace creation policy could not be read")
		}
		allowed, err := canCreateWorkspace(ctx, tx, s.driver, actorID, isAdministrator, policy)
		if err != nil {
			return errors.New("workspace creation grant could not be checked")
		}
		if !allowed {
			return ErrForbidden
		}

		var slugExists bool
		query := "SELECT EXISTS (SELECT 1 FROM registry_workspaces WHERE slug = " + bind(s.driver, 1) + ")"
		if err := tx.QueryRowContext(ctx, query, slug).Scan(&slugExists); err != nil {
			return errors.New("workspace slug availability could not be checked")
		}
		if slugExists {
			return ErrSlugConflict
		}

		workspaceID, err := uuid.NewV7()
		if err != nil {
			return errors.New("workspace identity could not be generated")
		}
		now := time.Now().UTC()
		createdAt := now.Format(time.RFC3339Nano)
		insertWorkspace := `INSERT INTO registry_workspaces
			(workspace_id, slug, display_name, status, created_by, created_at)
			VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, 'active', ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `)`
		if _, err := tx.ExecContext(ctx, insertWorkspace,
			workspaceID.String(), slug, displayName, actorID, createdAt); err != nil {
			return errors.New("workspace could not be created")
		}
		insertMembership := `INSERT INTO registry_workspace_memberships
			(workspace_id, user_id, role, status, created_by, created_at, updated_at)
			VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, 'owner', 'active', ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `)`
		if _, err := tx.ExecContext(ctx, insertMembership,
			workspaceID.String(), actorID, actorID, createdAt, createdAt); err != nil {
			return errors.New("initial workspace ownership could not be recorded")
		}
		if err := recordAudit(ctx, tx, s.driver, actorID, "workspace.created", "workspace", workspaceID.String()); err != nil {
			return err
		}
		workspace = Workspace{
			ID:          workspaceID.String(),
			Slug:        slug,
			DisplayName: displayName,
			Status:      "active",
			CreatedBy:   actorID,
			CreatedAt:   now,
		}
		return nil
	})
	if err != nil {
		return Workspace{}, err
	}
	return workspace, nil
}

func (s *Service) withWriteTransaction(ctx context.Context, operation func(*sql.Tx) error) (retErr error) {
	if s == nil || s.db == nil || operation == nil {
		return errors.New("workspace service is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("workspace transaction could not begin")
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			retErr = errors.Join(retErr, fmt.Errorf("workspace transaction rollback failed: %w", rollbackErr))
		}
	}()
	if err := lockInstallationRow(ctx, tx, s.driver); err != nil {
		return err
	}
	if err := operation(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("workspace transaction could not commit")
	}
	return nil
}

func lockInstallationRow(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver) error {
	if driver == config.Postgres {
		var singletonID int
		if err := tx.QueryRowContext(ctx,
			"SELECT singleton_id FROM registry_installation WHERE singleton_id = 1 FOR UPDATE").Scan(&singletonID); err != nil {
			return errors.New("installation coordination lock could not be acquired")
		}
		return nil
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE registry_installation SET workspace_creation_policy = workspace_creation_policy WHERE singleton_id = 1")
	if err != nil {
		return errors.New("installation coordination lock could not be acquired")
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected != 1 {
		return errors.New("installation coordination row is unavailable")
	}
	return nil
}

func requireActiveUser(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, userID string) error {
	var status string
	query := "SELECT status FROM registry_users WHERE user_id = " + bind(driver, 1)
	err := tx.QueryRowContext(ctx, query, userID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && status != "active") {
		return ErrUserUnavailable
	}
	if err != nil {
		return errors.New("user status could not be checked")
	}
	return nil
}

func requireActiveAdministrator(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, userID string) error {
	if err := requireActiveUser(ctx, tx, driver, userID); err != nil {
		return err
	}
	isAdministrator, err := isInstanceAdministrator(ctx, tx, driver, userID)
	if err != nil {
		return errors.New("administrator authorization could not be checked")
	}
	if !isAdministrator {
		return ErrForbidden
	}
	return nil
}

func isInstanceAdministrator(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, userID string) (bool, error) {
	var isAdministrator bool
	query := `SELECT EXISTS (
		SELECT 1 FROM registry_instance_admins AS administrators
		JOIN registry_users AS users ON users.user_id = administrators.user_id
		WHERE administrators.user_id = ` + bind(driver, 1) + ` AND users.status = 'active'
	)`
	err := tx.QueryRowContext(ctx, query, userID).Scan(&isAdministrator)
	return isAdministrator, err
}

func readCreationPolicy(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver) (CreationPolicy, error) {
	var policy string
	err := tx.QueryRowContext(ctx,
		"SELECT workspace_creation_policy FROM registry_installation WHERE singleton_id = 1").Scan(&policy)
	if err != nil {
		return "", err
	}
	parsed := CreationPolicy(policy)
	if !validPolicy(parsed) {
		return "", errors.New("stored workspace creation policy is invalid")
	}
	return parsed, nil
}

func canCreateWorkspace(
	ctx context.Context,
	tx *sql.Tx,
	driver config.DatabaseDriver,
	userID string,
	isAdministrator bool,
	policy CreationPolicy,
) (bool, error) {
	if isAdministrator {
		return true, nil
	}
	switch policy {
	case CreationAdminOnly:
		return false, nil
	case CreationAuthorizedUsers:
		var hasGrant bool
		query := "SELECT EXISTS (SELECT 1 FROM registry_workspace_creation_grants WHERE user_id = " + bind(driver, 1) + " AND revoked_at IS NULL)"
		err := tx.QueryRowContext(ctx, query, userID).Scan(&hasGrant)
		return hasGrant, err
	case CreationAnyUser:
		return true, nil
	default:
		return false, ErrInvalidPolicy
	}
}

func recordAudit(
	ctx context.Context,
	tx *sql.Tx,
	driver config.DatabaseDriver,
	actorID string,
	action string,
	targetType string,
	targetID string,
) error {
	eventID, err := uuid.NewV7()
	if err != nil {
		return errors.New("audit event identity could not be generated")
	}
	query := `INSERT INTO registry_audit_events
		(event_id, actor_user_id, action, target_type, target_id, outcome, occurred_at)
		VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, ` + bind(driver, 3) + `, ` + bind(driver, 4) + `, ` + bind(driver, 5) + `, 'succeeded', ` + bind(driver, 6) + `)`
	_, err = tx.ExecContext(ctx, query,
		eventID.String(), actorID, action, targetType, targetID, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return errors.New("audit event could not be recorded")
	}
	return nil
}

func normalizeDisplayName(displayName string) (string, error) {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" || utf8.RuneCountInString(displayName) > 200 {
		return "", ErrInvalidName
	}
	for _, character := range displayName {
		if unicode.IsControl(character) {
			return "", ErrInvalidName
		}
	}
	return displayName, nil
}

func parseUserID(userID string) (string, error) {
	parsed, err := uuid.Parse(userID)
	if err != nil || parsed == uuid.Nil {
		return "", ErrUnauthenticated
	}
	return parsed.String(), nil
}

func validPolicy(policy CreationPolicy) bool {
	switch policy {
	case CreationAdminOnly, CreationAuthorizedUsers, CreationAnyUser:
		return true
	default:
		return false
	}
}

func bind(driver config.DatabaseDriver, position int) string {
	if driver == config.Postgres {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}
