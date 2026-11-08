package npm

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
)

var ErrTagConflict = errors.New("npm dist-tag revision has changed")
var ErrTagUnavailable = errors.New("npm dist-tag is unavailable")

type DistTagState struct {
	Revision int64
	Active   bool
	Version  string
}

// GetDistTagState returns the revision and tombstone to an authorized tag
// manager. The version is absent for a removed tag. It does not grant read
// access to package contents or replace the public packument.
func (s *ReservationService) GetDistTagState(ctx context.Context, actor, workspace, repository, name, tag string) (DistTagState, error) {
	if s == nil || ctx == nil || !validTag(tag) || ValidatePackageName(name) != nil {
		return DistTagState{}, ErrTagUnavailable
	}
	var result DistTagState
	err := s.repositories.WithNPMTagManagerTransaction(ctx, actor, workspace, repository, func(tx *sql.Tx, _ string) error {
		query := `SELECT t.revision, t.active, v.version_identity FROM registry_npm_dist_tags t JOIN registry_npm_packages p ON p.package_id = t.package_id AND p.workspace_id = t.workspace_id AND p.repository_id = t.repository_id JOIN registry_npm_versions v ON v.npm_version_id = t.npm_version_id AND v.package_id = t.package_id AND v.workspace_id = t.workspace_id AND v.repository_id = t.repository_id WHERE t.workspace_id = ` + s.bind(1) + ` AND t.repository_id = ` + s.bind(2) + ` AND p.name = ` + s.bind(3) + ` AND t.tag = ` + s.bind(4)
		var active int
		var version string
		if err := tx.QueryRowContext(ctx, query, workspace, repository, name, tag).Scan(&result.Revision, &active, &version); errors.Is(err, sql.ErrNoRows) {
			return ErrTagUnavailable
		} else if err != nil {
			return errors.New("npm tag state could not be read")
		}
		if result.Revision < 1 || (active != 0 && active != 1) {
			return errors.New("npm tag state is invalid")
		}
		result.Active = active == 1
		if result.Active {
			result.Version = version
		}
		return nil
	})
	if err != nil {
		return DistTagState{}, err
	}
	return result, nil
}

// validTag accepts a deliberately conservative ASCII subset, and rejects
// SemVer-like tags so a client cannot confuse them with version selectors.
func validTag(tag string) bool {
	if len(tag) < 1 || len(tag) > 128 {
		return false
	}
	if len(tag) > 1 && tag[0] == 'v' {
		if _, err := VersionIdentity(tag[1:]); err == nil {
			return false
		}
	}
	for i, c := range []byte(tag) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9' && i > 0) || (i > 0 && (c == '-' || c == '_' || c == '.')) {
			continue
		}
		return false
	}
	return true
}

// SetDistTag moves a tag to a published version under a distinct human grant.
// expectedRevision is zero for creation; updates require the current revision.
// Callers exposing this operation must require recent human MFA and CSRF.
func (s *ReservationService) SetDistTag(ctx context.Context, actor, workspace, repository, name, tag, version string, expectedRevision int64) (int64, error) {
	if s == nil || ctx == nil || !validTag(tag) || ValidatePackageName(name) != nil || expectedRevision < 0 || expectedRevision == math.MaxInt64 {
		return 0, ErrTagUnavailable
	}
	identity, err := VersionIdentity(version)
	if err != nil || identity != version {
		return 0, ErrTagUnavailable
	}
	var next int64
	err = s.repositories.WithNPMTagManagerTransaction(ctx, actor, workspace, repository, func(tx *sql.Tx, grant string) error {
		query := `SELECT p.package_id, v.npm_version_id FROM registry_npm_packages p JOIN registry_npm_versions v ON v.package_id = p.package_id AND v.workspace_id = p.workspace_id AND v.repository_id = p.repository_id JOIN registry_npm_publications pub ON pub.npm_version_id = v.npm_version_id AND pub.workspace_id = v.workspace_id AND pub.repository_id = v.repository_id WHERE p.workspace_id = ` + s.bind(1) + ` AND p.repository_id = ` + s.bind(2) + ` AND p.name = ` + s.bind(3) + ` AND v.version_identity = ` + s.bind(4)
		var packageID, versionID string
		if err := tx.QueryRowContext(ctx, query, workspace, repository, name, identity).Scan(&packageID, &versionID); errors.Is(err, sql.ErrNoRows) {
			return ErrTagUnavailable
		} else if err != nil {
			return errors.New("npm tag target could not be read")
		}
		query = `SELECT revision FROM registry_npm_dist_tags WHERE package_id = ` + s.bind(1) + ` AND tag = ` + s.bind(2)
		var current int64
		err := tx.QueryRowContext(ctx, query, packageID, tag).Scan(&current)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return errors.New("npm tag revision could not be read")
		}
		if errors.Is(err, sql.ErrNoRows) {
			current = 0
		}
		if current != expectedRevision {
			return ErrTagConflict
		}
		next = current + 1
		if current == 0 {
			query = `INSERT INTO registry_npm_dist_tags (package_id, workspace_id, repository_id, tag, npm_version_id, revision) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `)`
			if _, err := tx.ExecContext(ctx, query, packageID, workspace, repository, tag, versionID, next); err != nil {
				return errors.New("npm tag could not be created")
			}
		} else {
			query = `UPDATE registry_npm_dist_tags SET npm_version_id = ` + s.bind(1) + `, revision = ` + s.bind(2) + `, active = 1 WHERE package_id = ` + s.bind(3) + ` AND tag = ` + s.bind(4) + ` AND revision = ` + s.bind(5)
			result, err := tx.ExecContext(ctx, query, versionID, next, packageID, tag, current)
			if err != nil {
				return errors.New("npm tag could not be updated")
			}
			count, err := result.RowsAffected()
			if err != nil || count != 1 {
				return ErrTagConflict
			}
		}
		id, err := uuid.NewV7()
		if err != nil {
			return errors.New("npm tag event identity could not be created")
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		query = `INSERT INTO registry_npm_tag_events (event_id, package_id, workspace_id, repository_id, tag, npm_version_id, revision, action, actor_user_id, grant_id, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `, ` + s.bind(7) + `, 'set', ` + s.bind(8) + `, ` + s.bind(9) + `, ` + s.bind(10) + `)`
		if _, err := tx.ExecContext(ctx, query, id.String(), packageID, workspace, repository, tag, versionID, next, actor, grant, now); err != nil {
			return errors.New("npm tag event could not be recorded")
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("npm tag audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'user', 'npm.tag.updated', 'npm_package', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), actor, packageID, now); err != nil {
			return errors.New("npm tag change could not be audited")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return next, nil
}

// RemoveDistTag records a tombstone at the next revision. Recreating a tag
// requires that revision, so stale writers cannot revive a deleted tag.
func (s *ReservationService) RemoveDistTag(ctx context.Context, actor, workspace, repository, name, tag string, expectedRevision int64) (int64, error) {
	if s == nil || ctx == nil || !validTag(tag) || ValidatePackageName(name) != nil || expectedRevision < 1 || expectedRevision == math.MaxInt64 {
		return 0, ErrTagUnavailable
	}
	next := expectedRevision + 1
	err := s.repositories.WithNPMTagManagerTransaction(ctx, actor, workspace, repository, func(tx *sql.Tx, grant string) error {
		query := `SELECT t.package_id, t.npm_version_id, t.revision, t.active FROM registry_npm_dist_tags t JOIN registry_npm_packages p ON p.package_id = t.package_id AND p.workspace_id = t.workspace_id AND p.repository_id = t.repository_id WHERE t.workspace_id = ` + s.bind(1) + ` AND t.repository_id = ` + s.bind(2) + ` AND p.name = ` + s.bind(3) + ` AND t.tag = ` + s.bind(4)
		var packageID, versionID string
		var revision int64
		var active int
		if err := tx.QueryRowContext(ctx, query, workspace, repository, name, tag).Scan(&packageID, &versionID, &revision, &active); errors.Is(err, sql.ErrNoRows) {
			return ErrTagUnavailable
		} else if err != nil {
			return errors.New("npm tag state could not be read")
		}
		if revision != expectedRevision {
			return ErrTagConflict
		}
		if active != 1 {
			return ErrTagUnavailable
		}
		query = `UPDATE registry_npm_dist_tags SET active = 0, revision = ` + s.bind(1) + ` WHERE package_id = ` + s.bind(2) + ` AND tag = ` + s.bind(3) + ` AND revision = ` + s.bind(4) + ` AND active = 1`
		result, err := tx.ExecContext(ctx, query, next, packageID, tag, expectedRevision)
		if err != nil {
			return errors.New("npm tag could not be removed")
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return ErrTagConflict
		}
		id, err := uuid.NewV7()
		if err != nil {
			return errors.New("npm tag event identity could not be created")
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		query = `INSERT INTO registry_npm_tag_events (event_id, package_id, workspace_id, repository_id, tag, npm_version_id, revision, action, actor_user_id, grant_id, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `, ` + s.bind(7) + `, 'removed', ` + s.bind(8) + `, ` + s.bind(9) + `, ` + s.bind(10) + `)`
		if _, err := tx.ExecContext(ctx, query, id.String(), packageID, workspace, repository, tag, versionID, next, actor, grant, now); err != nil {
			return errors.New("npm tag removal event could not be recorded")
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("npm tag audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'user', 'npm.tag.removed', 'npm_package', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), actor, packageID, now); err != nil {
			return errors.New("npm tag removal could not be audited")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return next, nil
}
