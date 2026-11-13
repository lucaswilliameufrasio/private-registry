package oci

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"private-registry/internal/repositories"
)

var (
	ErrQuota          = errors.New("OCI content would exceed the logical quota")
	ErrTagImmutable   = errors.New("OCI tag is immutable in this repository")
	ErrManifestInUse  = errors.New("OCI manifest is referenced by an index in this repository")
	ErrPolicyRevision = errors.New("OCI policy revision is stale")
	ErrTagUnknown     = errors.New("OCI tag is unknown")
)

// Policy holds per-repository publication rules. Revision 0 means no policy
// was ever written and the defaults apply.
type Policy struct {
	ImmutableTags bool
	Revision      int64
}

// quotaSources lists every catalog that consumes logical bytes in a
// workspace. OCI counts each blob once per repository it belongs to, plus the
// stored manifest documents, regardless of physical deduplication.
var quotaSources = []struct{ table, expression, condition string }{
	{"registry_generic_upload_sessions", "expected_size", " AND status IN ('receiving', 'uploading', 'uploaded', 'published')"},
	{"registry_go_module_versions", "zip_size + LENGTH(mod_bytes)", ""},
	{"registry_go_upload_sessions", "zip_size + LENGTH(mod_bytes)", " AND status IN ('receiving', 'uploading', 'uploaded')"},
	{"registry_cargo_versions", "archive_size", ""},
	{"registry_cargo_reservations", "archive_size", " AND status IN ('reserved', 'uploading', 'uploaded') AND NOT EXISTS (SELECT 1 FROM registry_cargo_publications p WHERE p.reservation_id = registry_cargo_reservations.reservation_id)"},
	{"registry_npm_versions", "tarball_size", ""},
	{"registry_npm_reservations", "tarball_size", " AND status IN ('reserved', 'uploading', 'uploaded') AND NOT EXISTS (SELECT 1 FROM registry_npm_publications p WHERE p.reservation_id = registry_npm_reservations.reservation_id)"},
	{"registry_pub_versions", "tarball_size", ""},
	{"registry_pub_reservations", "tarball_size", " AND status IN ('reserved', 'uploading', 'uploaded') AND NOT EXISTS (SELECT 1 FROM registry_pub_publications p WHERE p.reservation_id = registry_pub_reservations.reservation_id)"},
	{"registry_oci_blobs", "size_bytes", ""},
	{"registry_oci_manifests", "LENGTH(content)", ""},
}

// checkQuota runs inside the write-token transaction, under the shared
// authorization lock, so concurrent pushes cannot both pass. Each source is
// subtracted separately to avoid overflowing a combined sum.
func (s *Service) checkQuota(ctx context.Context, tx *sql.Tx, workspace, repository string, size int64) error {
	query := `SELECT w.logical_quota_bytes, r.logical_quota_bytes FROM registry_workspaces w JOIN registry_repositories r ON r.workspace_id = w.workspace_id WHERE w.workspace_id = ` + s.bind(1) + ` AND r.repository_id = ` + s.bind(2)
	var workspaceLimit, repositoryLimit sql.NullInt64
	if err := tx.QueryRowContext(ctx, query, workspace, repository).Scan(&workspaceLimit, &repositoryLimit); err != nil {
		return ErrUnavailable
	}
	for _, limit := range []struct {
		value      sql.NullInt64
		repository bool
	}{{workspaceLimit, false}, {repositoryLimit, true}} {
		if !limit.value.Valid {
			continue
		}
		if size > limit.value.Int64 {
			return ErrQuota
		}
		remaining := limit.value.Int64 - size
		for _, source := range quotaSources {
			isOCI := source.table == "registry_oci_blobs" || source.table == "registry_oci_manifests"
			if limit.repository && !isOCI {
				continue
			}
			query := `SELECT COALESCE(SUM(` + source.expression + `), 0) FROM ` + source.table + ` WHERE workspace_id = ` + s.bind(1) + source.condition
			args := []any{workspace}
			if limit.repository {
				query += ` AND repository_id = ` + s.bind(2)
				args = append(args, repository)
			}
			var used int64
			if err := tx.QueryRowContext(ctx, query, args...).Scan(&used); err != nil || used < 0 {
				return ErrUnavailable
			}
			if used > remaining {
				return ErrQuota
			}
			remaining -= used
		}
	}
	return nil
}

func (s *Service) readPolicy(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, repository string) (Policy, error) {
	var policy Policy
	var immutable int
	err := queryer.QueryRowContext(ctx, `SELECT immutable_tags, revision FROM registry_oci_policies WHERE repository_id = `+s.bind(1), repository).Scan(&immutable, &policy.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, nil
	} else if err != nil {
		return Policy{}, ErrUnavailable
	}
	policy.ImmutableTags = immutable == 1
	return policy, nil
}

// GetPolicy is for workspace owners and administrators.
func (s *Service) GetPolicy(ctx context.Context, actor, workspace, repository string) (Policy, error) {
	var policy Policy
	err := s.repos.WithRepositoryManagerTransaction(ctx, actor, workspace, repository, repositories.FormatOCI, func(tx *sql.Tx, _ string) error {
		var err error
		policy, err = s.readPolicy(ctx, tx, repository)
		return err
	})
	return policy, err
}

// SetPolicy changes the publication rules with optimistic concurrency.
// Turning immutability on does not alter existing tags; it only stops them
// from moving afterwards.
func (s *Service) SetPolicy(ctx context.Context, actor, workspace, repository string, expectedRevision int64, immutableTags bool) (Policy, error) {
	if expectedRevision < 0 {
		return Policy{}, ErrPolicyRevision
	}
	var policy Policy
	err := s.repos.WithRepositoryManagerTransaction(ctx, actor, workspace, repository, repositories.FormatOCI, func(tx *sql.Tx, user string) error {
		current, err := s.readPolicy(ctx, tx, repository)
		if err != nil {
			return err
		}
		if current.Revision != expectedRevision {
			return ErrPolicyRevision
		}
		if current.Revision > 0 && current.ImmutableTags == immutableTags {
			policy = current
			return nil
		}
		value := 0
		if immutableTags {
			value = 1
		}
		now := time.Now().UTC().UnixMilli()
		var result sql.Result
		if current.Revision == 0 {
			result, err = tx.ExecContext(ctx, `INSERT INTO registry_oci_policies (repository_id, workspace_id, immutable_tags, revision, updated_by, updated_at_ms) VALUES (`+s.binds(6)+`) ON CONFLICT (repository_id) DO NOTHING`, repository, workspace, value, 1, user, now)
		} else {
			result, err = tx.ExecContext(ctx, `UPDATE registry_oci_policies SET immutable_tags = `+s.bind(1)+`, revision = revision + 1, updated_by = `+s.bind(2)+`, updated_at_ms = `+s.bind(3)+` WHERE repository_id = `+s.bind(4)+` AND revision = `+s.bind(5), value, user, now, repository, expectedRevision)
		}
		if err != nil {
			return ErrUnavailable
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return ErrPolicyRevision
		}
		policy = Policy{ImmutableTags: immutableTags, Revision: expectedRevision + 1}
		return repositories.RecordAudit(ctx, tx, s.driver, user, "oci_policy.changed", "repository", repository)
	})
	return policy, err
}

// DeleteTag removes one tag. The manifest stays reachable by digest. Tags of
// a repository with immutable tags can still be deleted by a manager: that is
// the explicit, audited way to retire one.
func (s *Service) DeleteTag(ctx context.Context, actor, workspace, repository, image, tag string) error {
	if !ValidImageName(image) {
		return ErrNameInvalid
	}
	if !ValidTag(tag) {
		return ErrTagUnknown
	}
	return s.repos.WithRepositoryManagerTransaction(ctx, actor, workspace, repository, repositories.FormatOCI, func(tx *sql.Tx, user string) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM registry_oci_tags WHERE repository_id = `+s.bind(1)+` AND image_name = `+s.bind(2)+` AND tag = `+s.bind(3), repository, image, tag)
		if err != nil {
			return ErrUnavailable
		}
		if removed, err := result.RowsAffected(); err != nil {
			return ErrUnavailable
		} else if removed == 0 {
			return ErrTagUnknown
		}
		return repositories.RecordAudit(ctx, tx, s.driver, user, "oci_tag.deleted", "oci_tag", repository+"/"+image+":"+tag)
	})
}

// DeleteManifest removes a manifest and every tag of the repository that
// points to it. A manifest that an index of the repository still lists is
// refused, so a multi-platform image cannot lose a platform silently. Blobs
// are left to garbage collection.
func (s *Service) DeleteManifest(ctx context.Context, actor, workspace, repository, digest string) (int, error) {
	if !ValidDigest(digest) {
		return 0, ErrDigestInvalid
	}
	removedTags := 0
	err := s.repos.WithRepositoryManagerTransaction(ctx, actor, workspace, repository, repositories.FormatOCI, func(tx *sql.Tx, user string) error {
		var present, referenced bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_oci_manifests WHERE repository_id = `+s.bind(1)+` AND digest = `+s.bind(2)+`)`, repository, digest).Scan(&present); err != nil {
			return ErrUnavailable
		}
		if !present {
			return ErrManifestUnknown
		}
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_oci_manifest_references WHERE repository_id = `+s.bind(1)+` AND referenced_digest = `+s.bind(2)+` AND kind = 'manifest')`, repository, digest).Scan(&referenced); err != nil {
			return ErrUnavailable
		}
		if referenced {
			return ErrManifestInUse
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM registry_oci_tags WHERE repository_id = `+s.bind(1)+` AND manifest_digest = `+s.bind(2), repository, digest)
		if err != nil {
			return ErrUnavailable
		}
		tags, err := result.RowsAffected()
		if err != nil {
			return ErrUnavailable
		}
		removedTags = int(tags)
		if _, err := tx.ExecContext(ctx, `DELETE FROM registry_oci_manifest_references WHERE repository_id = `+s.bind(1)+` AND manifest_digest = `+s.bind(2), repository, digest); err != nil {
			return ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM registry_oci_manifests WHERE repository_id = `+s.bind(1)+` AND digest = `+s.bind(2), repository, digest); err != nil {
			return ErrUnavailable
		}
		return repositories.RecordAudit(ctx, tx, s.driver, user, "oci_manifest.deleted", "oci_manifest", repository+"@"+digest)
	})
	return removedTags, err
}

// CollectUnreferencedBlobs drops blob membership that no manifest of the same
// repository references and that is older than grace. The grace period
// protects pushes in progress, which upload blobs before their manifest. It
// frees quota and access only: the stored object is not deleted, because it
// may be shared with other formats in the workspace and deleting it safely
// needs leases that do not exist yet.
func (s *Service) CollectUnreferencedBlobs(ctx context.Context, now time.Time, grace time.Duration) (int64, error) {
	if s == nil || ctx == nil || grace < time.Minute {
		return 0, errors.New("OCI blob collection parameters are invalid")
	}
	cutoff := now.Add(-grace).UTC().UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM registry_oci_blobs WHERE created_at_ms < `+s.bind(1)+` AND NOT EXISTS (SELECT 1 FROM registry_oci_manifest_references AS r WHERE r.repository_id = registry_oci_blobs.repository_id AND r.referenced_digest = registry_oci_blobs.digest AND r.kind = 'blob')`, cutoff)
	if err != nil {
		return 0, ErrUnavailable
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return 0, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return 0, ErrUnavailable
	}
	return removed, nil
}
