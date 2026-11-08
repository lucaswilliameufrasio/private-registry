package repositories

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
	"private-registry/internal/workspaces"
)

type Visibility string

const (
	VisibilityPrivate  Visibility = "private"
	VisibilityUnlisted Visibility = "unlisted"
	VisibilityListed   Visibility = "listed"
)

type VisibilityPolicy string

type Format string

const (
	FormatGeneric Format = "generic"
	FormatGo      Format = "go"
	FormatCargo   Format = "cargo"
)

const (
	PolicyPrivateOnly        VisibilityPolicy = "private_only"
	PolicyPrivateAndUnlisted VisibilityPolicy = "private_and_unlisted"
	PolicyAll                VisibilityPolicy = "all"
)

var (
	ErrUnauthenticated         = errors.New("authenticated user is required")
	ErrForbidden               = errors.New("operation is not permitted")
	ErrInvalidWorkspaceID      = errors.New("workspace identity is invalid")
	ErrInvalidRepositoryID     = errors.New("repository identity is invalid")
	ErrInvalidSlug             = errors.New("repository slug is invalid")
	ErrInvalidName             = errors.New("repository display name is invalid")
	ErrInvalidFormat           = errors.New("repository format is invalid or unsupported")
	ErrFormatMismatch          = errors.New("repository format does not support this operation")
	ErrInvalidPageSize         = errors.New("repository page size is invalid")
	ErrInvalidVisibility       = errors.New("repository visibility is invalid")
	ErrInvalidVisibilityPolicy = errors.New("repository visibility policy is invalid")
	ErrRepositoryUnavailable   = errors.New("repository is unavailable")
	ErrUserUnavailable         = errors.New("user is unavailable")
	ErrSlugConflict            = errors.New("repository slug is already reserved")
	ErrVisibilityNotAllowed    = errors.New("repository visibility is not allowed")
	ErrPublicConfirmation      = errors.New("public visibility requires explicit confirmation")

	repositorySlugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

const maxRepositoryPageSize = 100

type Repository struct {
	ID          string
	WorkspaceID string
	Slug        string
	DisplayName string
	Format      Format
	Visibility  Visibility
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
		return nil, errors.New("repository database is required")
	}
	if driver != config.SQLite && driver != config.Postgres {
		return nil, errors.New("repository database driver must be sqlite or postgres")
	}
	return &Service{db: db, driver: driver}, nil
}

func (s *Service) Create(
	ctx context.Context,
	actorUserID string,
	workspaceID string,
	slug string,
	displayName string,
) (repository Repository, retErr error) {
	return s.CreateWithFormat(ctx, actorUserID, workspaceID, slug, displayName, FormatGeneric)
}

func (s *Service) CreateWithFormat(
	ctx context.Context,
	actorUserID string,
	workspaceID string,
	slug string,
	displayName string,
	format Format,
) (repository Repository, retErr error) {
	if ctx == nil {
		return Repository{}, errors.New("repository creation context is required")
	}
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return Repository{}, ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return Repository{}, ErrInvalidWorkspaceID
	}
	slug = strings.TrimSpace(slug)
	if !repositorySlugPattern.MatchString(slug) {
		return Repository{}, ErrInvalidSlug
	}
	displayName, err = normalizeDisplayName(displayName)
	if err != nil {
		return Repository{}, err
	}
	if format != FormatGeneric && format != FormatGo {
		return Repository{}, ErrInvalidFormat
	}

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

		var slugExists bool
		query := `SELECT EXISTS (SELECT 1 FROM registry_repositories
			WHERE workspace_id = ` + bind(s.driver, 1) + ` AND slug = ` + bind(s.driver, 2) + `)`
		if err := tx.QueryRowContext(ctx, query, workspaceID, slug).Scan(&slugExists); err != nil {
			return errors.New("repository slug availability could not be checked")
		}
		if slugExists {
			return ErrSlugConflict
		}

		repositoryID, err := uuid.NewV7()
		if err != nil {
			return errors.New("repository identity could not be generated")
		}
		now := time.Now().UTC()
		createdAt := now.Format(time.RFC3339Nano)
		query = `INSERT INTO registry_repositories
			(repository_id, workspace_id, slug, display_name, visibility, status, created_by, created_at, updated_at, format)
			VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, 'private', 'active', ` + bind(s.driver, 5) + `, ` + bind(s.driver, 6) + `, ` + bind(s.driver, 7) + `, ` + bind(s.driver, 8) + `)`
		if _, err := tx.ExecContext(ctx, query,
			repositoryID.String(), workspaceID, slug, displayName, actorID, createdAt, createdAt, string(format)); err != nil {
			return errors.New("repository could not be created")
		}
		if err := recordAudit(ctx, tx, s.driver, actorID,
			"repository.created", "repository", repositoryID.String()); err != nil {
			return err
		}
		repository = Repository{
			ID:          repositoryID.String(),
			WorkspaceID: workspaceID,
			Slug:        slug,
			DisplayName: displayName,
			Format:      format,
			Visibility:  VisibilityPrivate,
			Status:      "active",
			CreatedBy:   actorID,
			CreatedAt:   now,
		}
		return nil
	})
	if err != nil {
		return Repository{}, err
	}
	return repository, nil
}

func (s *Service) UpdateDisplayName(
	ctx context.Context,
	actorUserID string,
	workspaceID string,
	repositoryID string,
	displayName string,
) error {
	if ctx == nil {
		return errors.New("repository update context is required")
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
	displayName, err = normalizeDisplayName(displayName)
	if err != nil {
		return err
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

		var currentName string
		query := `SELECT display_name FROM registry_repositories
			WHERE workspace_id = ` + bind(s.driver, 1) + `
				AND repository_id = ` + bind(s.driver, 2) + ` AND status = 'active'`
		err = tx.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&currentName)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRepositoryUnavailable
		}
		if err != nil {
			return errors.New("repository display name could not be read")
		}
		if currentName == displayName {
			return nil
		}

		now := time.Now().UTC().Format(time.RFC3339Nano)
		query = `UPDATE registry_repositories SET display_name = ` + bind(s.driver, 1) + `,
			updated_at = ` + bind(s.driver, 2) + `
			WHERE repository_id = ` + bind(s.driver, 3) + ` AND workspace_id = ` + bind(s.driver, 4) + ` AND status = 'active'`
		if _, err := tx.ExecContext(ctx, query, displayName, now, repositoryID, workspaceID); err != nil {
			return errors.New("repository display name could not be updated")
		}
		return recordAudit(ctx, tx, s.driver, actorID,
			"repository.display_name.changed", "repository", repositoryID)
	})
}

func (s *Service) ListForWorkspace(
	ctx context.Context,
	actorUserID string,
	workspaceID string,
	afterRepositoryID string,
	pageSize int,
) ([]Repository, bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, false, errors.New("repository list service is unavailable")
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
	if pageSize < 1 || pageSize > maxRepositoryPageSize {
		return nil, false, ErrInvalidPageSize
	}
	if afterRepositoryID != "" {
		afterRepositoryID, err = parseUUID(afterRepositoryID, ErrInvalidRepositoryID)
		if err != nil {
			return nil, false, ErrInvalidRepositoryID
		}
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

	query := `SELECT repository_id, workspace_id, slug, display_name, visibility, status, created_by, created_at, format
		FROM registry_repositories
		WHERE workspace_id = ` + bind(s.driver, 1) + ` AND status = 'active'`
	args := []any{workspaceID}
	if afterRepositoryID != "" {
		query += " AND repository_id > " + bind(s.driver, 2)
		args = append(args, afterRepositoryID)
	}
	query += " ORDER BY repository_id ASC LIMIT " + bind(s.driver, len(args)+1)
	args = append(args, pageSize+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, errors.New("repositories could not be read")
	}
	defer rows.Close()

	repositories := make([]Repository, 0, pageSize+1)
	for rows.Next() {
		var repository Repository
		var createdAt string
		if err := rows.Scan(
			&repository.ID,
			&repository.WorkspaceID,
			&repository.Slug,
			&repository.DisplayName,
			&repository.Visibility,
			&repository.Status,
			&repository.CreatedBy,
			&createdAt,
			&repository.Format,
		); err != nil {
			return nil, false, errors.New("repository record is invalid")
		}
		if _, err := parseUUID(repository.ID, ErrInvalidRepositoryID); err != nil {
			return nil, false, errors.New("repository identity is invalid")
		}
		if _, err := parseUUID(repository.WorkspaceID, ErrInvalidWorkspaceID); err != nil {
			return nil, false, errors.New("repository workspace identity is invalid")
		}
		if !validVisibility(repository.Visibility) || repository.Status != "active" || (repository.Format != FormatGeneric && repository.Format != FormatGo) {
			return nil, false, errors.New("repository state is invalid")
		}
		parsedCreatedAt, err := time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, false, errors.New("repository creation timestamp is invalid")
		}
		repository.CreatedAt = parsedCreatedAt.UTC()
		repositories = append(repositories, repository)
	}
	if err := rows.Err(); err != nil {
		return nil, false, errors.New("repositories could not be read")
	}
	if len(repositories) <= pageSize {
		return repositories, false, nil
	}
	return repositories[:pageSize], true, nil
}

func (s *Service) SetVisibility(
	ctx context.Context,
	actorUserID string,
	workspaceID string,
	repositoryID string,
	visibility Visibility,
	confirmedPublic bool,
) error {
	if ctx == nil {
		return errors.New("repository visibility context is required")
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
	if !validVisibility(visibility) {
		return ErrInvalidVisibility
	}

	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		actorRole, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, actorID)
		if err != nil {
			return err
		}
		if actorRole != workspaces.RoleOwner {
			return ErrForbidden
		}
		if visibility != VisibilityPrivate {
			if err := RequireFormat(ctx, tx, s.driver, workspaceID, repositoryID, FormatGeneric); errors.Is(err, ErrFormatMismatch) {
				return ErrVisibilityNotAllowed
			} else if err != nil {
				return err
			}
		}

		currentVisibility, err := readRepositoryVisibility(ctx, tx, s.driver, workspaceID, repositoryID)
		if err != nil {
			return err
		}
		if currentVisibility == visibility {
			return nil
		}
		policy, err := readVisibilityPolicy(ctx, tx, s.driver)
		if err != nil {
			return errors.New("repository visibility policy could not be read")
		}
		if !visibilityAllowed(policy, visibility) {
			return ErrVisibilityNotAllowed
		}
		if visibility != VisibilityPrivate && !confirmedPublic {
			return ErrPublicConfirmation
		}

		now := time.Now().UTC().Format(time.RFC3339Nano)
		query := `UPDATE registry_repositories SET visibility = ` + bind(s.driver, 1) + `,
			updated_at = ` + bind(s.driver, 2) + `
			WHERE repository_id = ` + bind(s.driver, 3) + ` AND workspace_id = ` + bind(s.driver, 4) + ` AND status = 'active'`
		result, err := tx.ExecContext(ctx, query, string(visibility), now, repositoryID, workspaceID)
		if err != nil {
			return errors.New("repository visibility could not be changed")
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil || rowsAffected != 1 {
			return ErrRepositoryUnavailable
		}
		return recordAudit(ctx, tx, s.driver, actorID,
			"repository.visibility.changed", "repository", repositoryID)
	})
}

func (s *Service) SetVisibilityPolicy(
	ctx context.Context,
	actorUserID string,
	policy VisibilityPolicy,
) error {
	if ctx == nil {
		return errors.New("repository visibility policy context is required")
	}
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return ErrUnauthenticated
	}
	if !validVisibilityPolicy(policy) {
		return ErrInvalidVisibilityPolicy
	}

	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveAdministrator(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		currentPolicy, err := readVisibilityPolicy(ctx, tx, s.driver)
		if err != nil {
			return errors.New("repository visibility policy could not be read")
		}
		if currentPolicy == policy {
			return nil
		}
		query := "UPDATE registry_installation SET repository_visibility_policy = " + bind(s.driver, 1) + " WHERE singleton_id = 1"
		if _, err := tx.ExecContext(ctx, query, string(policy)); err != nil {
			return errors.New("repository visibility policy could not be updated")
		}
		return recordAudit(ctx, tx, s.driver, actorID,
			"repository_visibility_policy.changed", "installation", "1")
	})
}

func (s *Service) VisibilityPolicy(ctx context.Context, actorUserID string) (VisibilityPolicy, error) {
	if s == nil || s.db == nil || ctx == nil {
		return "", errors.New("repository visibility policy service is unavailable")
	}
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return "", ErrUnauthenticated
	}
	if err := requireActiveUserDB(ctx, s.db, s.driver, actorID); err != nil {
		return "", err
	}
	isAdministrator, err := isInstanceAdministratorDB(ctx, s.db, s.driver, actorID)
	if err != nil {
		return "", errors.New("installation administrator authorization could not be checked")
	}
	if !isAdministrator {
		return "", ErrForbidden
	}
	policy, err := readVisibilityPolicyDB(ctx, s.db)
	if err != nil {
		return "", errors.New("repository visibility policy could not be read")
	}
	return policy, nil
}

func (s *Service) withWriteTransaction(ctx context.Context, operation func(*sql.Tx) error) (retErr error) {
	if s == nil || s.db == nil || operation == nil {
		return errors.New("repository service is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("repository transaction could not begin")
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			retErr = errors.Join(retErr, fmt.Errorf("repository transaction rollback failed: %w", rollbackErr))
		}
	}()
	if err := lockInstallationRow(ctx, tx, s.driver); err != nil {
		return err
	}
	if err := operation(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("repository transaction could not commit")
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
		"UPDATE registry_installation SET repository_visibility_policy = repository_visibility_policy WHERE singleton_id = 1")
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
	err := tx.QueryRowContext(ctx,
		"SELECT status FROM registry_users WHERE user_id = "+bind(driver, 1), userID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && status != "active") {
		return ErrUserUnavailable
	}
	if err != nil {
		return errors.New("user status could not be checked")
	}
	return nil
}

func requireActiveUserDB(ctx context.Context, db *sql.DB, driver config.DatabaseDriver, userID string) error {
	var status string
	err := db.QueryRowContext(ctx,
		"SELECT status FROM registry_users WHERE user_id = "+bind(driver, 1), userID).Scan(&status)
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
	var isAdministrator bool
	query := `SELECT EXISTS (
		SELECT 1 FROM registry_instance_admins AS administrators
		JOIN registry_users AS users ON users.user_id = administrators.user_id
		WHERE administrators.user_id = ` + bind(driver, 1) + ` AND users.status = 'active'
	)`
	if err := tx.QueryRowContext(ctx, query, userID).Scan(&isAdministrator); err != nil {
		return errors.New("installation administrator authorization could not be checked")
	}
	if !isAdministrator {
		return ErrForbidden
	}
	return nil
}

func isInstanceAdministratorDB(ctx context.Context, db *sql.DB, driver config.DatabaseDriver, userID string) (bool, error) {
	var isAdministrator bool
	query := `SELECT EXISTS (
		SELECT 1 FROM registry_instance_admins AS administrators
		JOIN registry_users AS users ON users.user_id = administrators.user_id
		WHERE administrators.user_id = ` + bind(driver, 1) + ` AND users.status = 'active'
	)`
	err := db.QueryRowContext(ctx, query, userID).Scan(&isAdministrator)
	return isAdministrator, err
}

func activeWorkspaceRole(
	ctx context.Context,
	tx *sql.Tx,
	driver config.DatabaseDriver,
	workspaceID string,
	userID string,
) (string, error) {
	query := `SELECT memberships.role
		FROM registry_workspace_memberships AS memberships
		JOIN registry_workspaces AS workspaces ON workspaces.workspace_id = memberships.workspace_id
		JOIN registry_users AS users ON users.user_id = memberships.user_id
		WHERE memberships.workspace_id = ` + bind(driver, 1) + `
			AND memberships.user_id = ` + bind(driver, 2) + `
			AND memberships.status = 'active'
			AND workspaces.status = 'active'
			AND users.status = 'active'`
	var role string
	err := tx.QueryRowContext(ctx, query, workspaceID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrForbidden
	}
	if err != nil {
		return "", errors.New("workspace membership authority could not be checked")
	}
	if role != workspaces.RoleOwner && role != workspaces.RoleAdministrator && role != workspaces.RoleMember {
		return "", errors.New("stored workspace membership role is invalid")
	}
	return role, nil
}

func activeWorkspaceRoleDB(
	ctx context.Context,
	db *sql.DB,
	driver config.DatabaseDriver,
	workspaceID string,
	userID string,
) (string, error) {
	query := `SELECT memberships.role
		FROM registry_workspace_memberships AS memberships
		JOIN registry_workspaces AS workspaces ON workspaces.workspace_id = memberships.workspace_id
		JOIN registry_users AS users ON users.user_id = memberships.user_id
		WHERE memberships.workspace_id = ` + bind(driver, 1) + `
			AND memberships.user_id = ` + bind(driver, 2) + `
			AND memberships.status = 'active'
			AND workspaces.status = 'active'
			AND users.status = 'active'`
	var role string
	err := db.QueryRowContext(ctx, query, workspaceID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrForbidden
	}
	if err != nil {
		return "", errors.New("workspace membership authority could not be checked")
	}
	if role != workspaces.RoleOwner && role != workspaces.RoleAdministrator && role != workspaces.RoleMember {
		return "", errors.New("stored workspace membership role is invalid")
	}
	return role, nil
}

func readRepositoryVisibility(
	ctx context.Context,
	tx *sql.Tx,
	driver config.DatabaseDriver,
	workspaceID string,
	repositoryID string,
) (Visibility, error) {
	var visibility string
	query := `SELECT visibility FROM registry_repositories
		WHERE workspace_id = ` + bind(driver, 1) + `
			AND repository_id = ` + bind(driver, 2) + ` AND status = 'active'`
	err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&visibility)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrRepositoryUnavailable
	}
	if err != nil {
		return "", errors.New("repository visibility could not be read")
	}
	parsed := Visibility(visibility)
	if !validVisibility(parsed) {
		return "", errors.New("stored repository visibility is invalid")
	}
	return parsed, nil
}

func readVisibilityPolicy(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver) (VisibilityPolicy, error) {
	var policy string
	err := tx.QueryRowContext(ctx,
		"SELECT repository_visibility_policy FROM registry_installation WHERE singleton_id = 1").Scan(&policy)
	if err != nil {
		return "", err
	}
	parsed := VisibilityPolicy(policy)
	if !validVisibilityPolicy(parsed) {
		return "", errors.New("stored repository visibility policy is invalid")
	}
	return parsed, nil
}

func readVisibilityPolicyDB(ctx context.Context, db *sql.DB) (VisibilityPolicy, error) {
	var policy string
	err := db.QueryRowContext(ctx,
		"SELECT repository_visibility_policy FROM registry_installation WHERE singleton_id = 1").Scan(&policy)
	if err != nil {
		return "", err
	}
	parsed := VisibilityPolicy(policy)
	if !validVisibilityPolicy(parsed) {
		return "", errors.New("stored repository visibility policy is invalid")
	}
	return parsed, nil
}

func visibilityAllowed(policy VisibilityPolicy, visibility Visibility) bool {
	switch visibility {
	case VisibilityPrivate:
		return true
	case VisibilityUnlisted:
		return policy == PolicyPrivateAndUnlisted || policy == PolicyAll
	case VisibilityListed:
		return policy == PolicyAll
	default:
		return false
	}
}

func validVisibility(visibility Visibility) bool {
	switch visibility {
	case VisibilityPrivate, VisibilityUnlisted, VisibilityListed:
		return true
	default:
		return false
	}
}

func validVisibilityPolicy(policy VisibilityPolicy) bool {
	switch policy {
	case PolicyPrivateOnly, PolicyPrivateAndUnlisted, PolicyAll:
		return true
	default:
		return false
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
	if _, err := tx.ExecContext(ctx, query,
		eventID.String(), actorID, action, targetType, targetID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return errors.New("audit event could not be recorded")
	}
	return nil
}

func parseUUID(value string, invalid error) (string, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil {
		return "", invalid
	}
	return parsed.String(), nil
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

func bind(driver config.DatabaseDriver, position int) string {
	if driver == config.Postgres {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}
