package repositories

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sort"
	"strings"

	"golang.org/x/mod/module"
	"private-registry/internal/config"
	"private-registry/internal/workspaces"
)

var (
	ErrGoNamespacePolicy   = errors.New("Go namespace policy is invalid")
	ErrGoNamespaceRevision = errors.New("Go namespace policy revision is stale")
	ErrGoNamespaceConfirm  = errors.New("Go public fallback requires explicit confirmation")
	ErrGoNamespaceOutside  = errors.New("Go module is outside the configured private namespaces")
	ErrGoNamespaceInUse    = errors.New("Go namespace policy would expose a known private identity")
)

type GoNamespacePolicy struct {
	Mode     string
	Prefixes []string
	Revision int64
}

func readGoNamespacePolicy(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, workspaceID, repositoryID string) (GoNamespacePolicy, error) {
	var policy GoNamespacePolicy
	policy.Prefixes = make([]string, 0)
	query := `SELECT go_namespace_mode, go_namespace_revision FROM registry_repositories WHERE workspace_id = ` + bind(driver, 1) + ` AND repository_id = ` + bind(driver, 2) + ` AND status = 'active'`
	if err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&policy.Mode, &policy.Revision); err != nil {
		return GoNamespacePolicy{}, errors.New("Go namespace policy could not be read")
	}
	query = `SELECT prefix FROM registry_go_private_prefixes WHERE workspace_id = ` + bind(driver, 1) + ` AND repository_id = ` + bind(driver, 2) + ` ORDER BY prefix LIMIT 33`
	rows, err := tx.QueryContext(ctx, query, workspaceID, repositoryID)
	if err != nil {
		return GoNamespacePolicy{}, errors.New("Go namespace prefixes could not be read")
	}
	defer rows.Close()
	for rows.Next() {
		var prefix string
		if err := rows.Scan(&prefix); err != nil || len(prefix) > 1024 || module.CheckPath(prefix) != nil || len(policy.Prefixes) >= 32 {
			return GoNamespacePolicy{}, errors.New("stored Go namespace prefix is invalid")
		}
		policy.Prefixes = append(policy.Prefixes, prefix)
	}
	if err := rows.Err(); err != nil {
		return GoNamespacePolicy{}, errors.New("Go namespace prefixes could not be iterated")
	}
	if (policy.Mode == "private_all" && len(policy.Prefixes) != 0) || (policy.Mode == "private_prefixes" && len(policy.Prefixes) == 0) || (policy.Mode != "private_all" && policy.Mode != "private_prefixes") {
		return GoNamespacePolicy{}, errors.New("stored Go namespace policy is invalid")
	}
	return policy, nil
}

func goNamespaceMatches(policy GoNamespacePolicy, path string, ancestors bool) bool {
	if policy.Mode == "private_all" {
		return true
	}
	for _, prefix := range policy.Prefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") || (ancestors && strings.HasPrefix(prefix, path+"/")) {
			return true
		}
	}
	return false
}

// RequireGoPrivateNamespace must run in an already authorized write transaction.
func RequireGoPrivateNamespace(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, workspaceID, repositoryID, path string) error {
	if ctx == nil || tx == nil || len(path) > 1024 || module.CheckPath(path) != nil {
		return ErrGoNamespacePolicy
	}
	policy, err := readGoNamespacePolicy(ctx, tx, driver, workspaceID, repositoryID)
	if err != nil {
		return err
	}
	if !goNamespaceMatches(policy, path, false) {
		return ErrGoNamespaceOutside
	}
	return nil
}

// IsGoPrivateNamespace authorizes the reader before classifying a missing path.
// Ancestors of private prefixes are private too, preventing discovery fallback.
func (s *Service) IsGoPrivateNamespace(ctx context.Context, actorID, workspaceID, repositoryID, path string) (bool, error) {
	if len(path) > 1024 || module.CheckPath(path) != nil {
		return true, ErrGoNamespacePolicy
	}
	private := true
	err := s.WithRepositoryGrantTransaction(ctx, actorID, workspaceID, repositoryID, GrantReader, func(tx *sql.Tx) error {
		if err := RequireFormat(ctx, tx, s.driver, workspaceID, repositoryID, FormatGo); err != nil {
			return err
		}
		policy, err := readGoNamespacePolicy(ctx, tx, s.driver, workspaceID, repositoryID)
		if err != nil {
			return err
		}
		private = goNamespaceMatches(policy, path, true)
		return nil
	})
	if err != nil {
		return true, err
	}
	return private, nil
}

func (s *Service) GoNamespacePolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string) (GoNamespacePolicy, error) {
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return GoNamespacePolicy{}, ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return GoNamespacePolicy{}, ErrInvalidWorkspaceID
	}
	repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
	if err != nil {
		return GoNamespacePolicy{}, ErrInvalidRepositoryID
	}
	var policy GoNamespacePolicy
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireGoNamespaceAdministrator(ctx, tx, s.driver, actorID, workspaceID, repositoryID); err != nil {
			return err
		}
		var err error
		policy, err = readGoNamespacePolicy(ctx, tx, s.driver, workspaceID, repositoryID)
		return err
	})
	return policy, err
}

func requireGoNamespaceAdministrator(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, actorID, workspaceID, repositoryID string) error {
	if err := requireActiveUser(ctx, tx, driver, actorID); err != nil {
		return err
	}
	role, err := activeWorkspaceRole(ctx, tx, driver, workspaceID, actorID)
	if err != nil {
		return err
	}
	if role != workspaces.RoleOwner && role != workspaces.RoleAdministrator {
		return ErrForbidden
	}
	return RequireFormat(ctx, tx, driver, workspaceID, repositoryID, FormatGo)
}

// SetGoNamespacePolicy requires explicit confirmation before permitting public
// fallback and refuses a policy that would exclude any known Go identity.
func (s *Service) SetGoNamespacePolicy(ctx context.Context, actorUserID, workspaceID, repositoryID string, expectedRevision int64, mode string, prefixes []string, confirmFallback bool) (GoNamespacePolicy, error) {
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return GoNamespacePolicy{}, ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return GoNamespacePolicy{}, ErrInvalidWorkspaceID
	}
	repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
	if err != nil {
		return GoNamespacePolicy{}, ErrInvalidRepositoryID
	}
	if ctx == nil || expectedRevision < 0 || expectedRevision == math.MaxInt64 || (mode != "private_all" && mode != "private_prefixes") || len(prefixes) > 32 || (mode == "private_all" && len(prefixes) != 0) || (mode == "private_prefixes" && len(prefixes) == 0) {
		return GoNamespacePolicy{}, ErrGoNamespacePolicy
	}
	if mode == "private_prefixes" && !confirmFallback {
		return GoNamespacePolicy{}, ErrGoNamespaceConfirm
	}
	prefixes = append([]string(nil), prefixes...)
	sort.Strings(prefixes)
	for index, prefix := range prefixes {
		if len(prefix) > 1024 || module.CheckPath(prefix) != nil || (index > 0 && prefixes[index-1] == prefix) {
			return GoNamespacePolicy{}, ErrGoNamespacePolicy
		}
	}
	policy := GoNamespacePolicy{Mode: mode, Prefixes: prefixes, Revision: expectedRevision}
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireGoNamespaceAdministrator(ctx, tx, s.driver, actorID, workspaceID, repositoryID); err != nil {
			return err
		}
		old, err := readGoNamespacePolicy(ctx, tx, s.driver, workspaceID, repositoryID)
		if err != nil {
			return err
		}
		if old.Revision != expectedRevision {
			return ErrGoNamespaceRevision
		}
		if old.Mode == mode && equalGoPrefixes(old.Prefixes, prefixes) {
			policy = old
			return nil
		}
		if mode == "private_prefixes" {
			for _, table := range []string{"registry_go_module_versions", "registry_go_upload_sessions"} {
				query := `SELECT module_path FROM ` + table + ` WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` LIMIT 10001`
				rows, err := tx.QueryContext(ctx, query, workspaceID, repositoryID)
				if err != nil {
					return errors.New("known Go identities could not be checked")
				}
				count := 0
				for rows.Next() {
					count++
					var path string
					if err := rows.Scan(&path); err != nil || count > 10000 || !goNamespaceMatches(policy, path, false) {
						_ = rows.Close()
						return ErrGoNamespaceInUse
					}
				}
				if err := rows.Err(); err != nil {
					_ = rows.Close()
					return errors.New("known Go identities could not be iterated")
				}
				if err := rows.Close(); err != nil {
					return errors.New("known Go identities could not be closed")
				}
			}
		}
		query := `UPDATE registry_repositories SET go_namespace_mode = ` + bind(s.driver, 1) + `, go_namespace_revision = go_namespace_revision + 1 WHERE workspace_id = ` + bind(s.driver, 2) + ` AND repository_id = ` + bind(s.driver, 3) + ` AND go_namespace_revision = ` + bind(s.driver, 4)
		result, err := tx.ExecContext(ctx, query, mode, workspaceID, repositoryID, expectedRevision)
		if err != nil {
			return errors.New("Go namespace policy could not be changed")
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return ErrGoNamespaceRevision
		}
		query = `DELETE FROM registry_go_private_prefixes WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2)
		if _, err := tx.ExecContext(ctx, query, workspaceID, repositoryID); err != nil {
			return errors.New("Go namespace prefixes could not be replaced")
		}
		for _, prefix := range prefixes {
			query = `INSERT INTO registry_go_private_prefixes (workspace_id, repository_id, prefix) VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `)`
			if _, err := tx.ExecContext(ctx, query, workspaceID, repositoryID, prefix); err != nil {
				return errors.New("Go namespace prefix could not be recorded")
			}
		}
		if err := recordAudit(ctx, tx, s.driver, actorID, "go.namespace_policy.changed", "repository", repositoryID); err != nil {
			return err
		}
		policy.Revision++
		return nil
	})
	if err != nil {
		return GoNamespacePolicy{}, err
	}
	if policy.Prefixes == nil {
		policy.Prefixes = []string{}
	}
	return policy, nil
}

func equalGoPrefixes(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
