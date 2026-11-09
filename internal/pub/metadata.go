package pub

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"private-registry/internal/repositories"
)

const maxPublishedVersions = 10000
const maxPublishedMetadataBytes = 16 << 20

type PublishedVersion struct {
	Version  string
	Manifest []byte
	SHA256   string
	Size     int64
}

// ReadPublishedVersionsWithToken returns only published versions, after
// revalidating the original reader grant. It never fetches an upstream or
// exposes pending receipts; callers must construct and bound wire responses.
func (s *ReservationService) ReadPublishedVersionsWithToken(ctx context.Context, token, workspace, repository, name string) ([]PublishedVersion, error) {
	if s == nil || ctx == nil || ValidateName(name) != nil {
		return nil, ErrPackageUnavailable
	}
	var result []PublishedVersion
	read := func(tx *sql.Tx, _ string) error {
		if err := repositories.RequireFormat(ctx, tx, s.driver, workspace, repository, repositories.FormatPub); err != nil {
			return err
		}
		query := `SELECT v.version, v.manifest, v.tarball_sha256, v.tarball_size FROM registry_pub_packages p JOIN registry_pub_versions v ON v.package_id = p.package_id AND v.workspace_id = p.workspace_id AND v.repository_id = p.repository_id JOIN registry_pub_publications pp ON pp.pub_version_id = v.pub_version_id AND pp.workspace_id = v.workspace_id AND pp.repository_id = v.repository_id WHERE p.workspace_id = ` + s.bind(1) + ` AND p.repository_id = ` + s.bind(2) + ` AND p.name = ` + s.bind(3) + ` ORDER BY v.version_identity LIMIT ` + s.bind(4)
		rows, err := tx.QueryContext(ctx, query, workspace, repository, name, maxPublishedVersions+1)
		if err != nil {
			return errors.New("Pub published metadata could not be read")
		}
		defer rows.Close()
		total := 0
		for rows.Next() {
			if len(result) == maxPublishedVersions {
				return errors.New("Pub package exceeds version limit")
			}
			var item PublishedVersion
			var manifest string
			if err := rows.Scan(&item.Version, &manifest, &item.SHA256, &item.Size); err != nil {
				return errors.New("Pub published metadata is invalid")
			}
			if len(manifest) > maxPublishedMetadataBytes-total || !validDigest(item.SHA256) || item.Size < 1 || item.Size > 64<<20 {
				return errors.New("Pub published metadata exceeds limits")
			}
			if err := ValidatePubspec([]byte(manifest), name, item.Version); err != nil {
				return errors.New("Pub published manifest is invalid")
			}
			total += len(manifest)
			item.Manifest = []byte(manifest)
			result = append(result, item)
		}
		if err := rows.Err(); err != nil {
			return errors.New("Pub published metadata could not be iterated")
		}
		if len(result) == 0 {
			return ErrPackageUnavailable
		}
		return nil
	}
	var err error
	if strings.HasPrefix(token, "prpw_") {
		err = s.repositories.WithPubWriteTokenTransaction(ctx, token, workspace, repository, func(tx *sql.Tx, actor string) error {
			tokenID, _, _ := strings.Cut(strings.TrimPrefix(token, "prpw_"), ".")
			query := `SELECT EXISTS (SELECT 1 FROM registry_pub_write_tokens t JOIN registry_repository_grants g ON g.grant_id = t.reader_grant_id WHERE t.token_id = ` + s.bind(1) + ` AND g.user_id = ` + s.bind(2) + ` AND g.workspace_id = ` + s.bind(3) + ` AND g.repository_id = ` + s.bind(4) + ` AND g.role = 'reader' AND g.revoked_at IS NULL)`
			var granted bool
			if err := tx.QueryRowContext(ctx, query, tokenID, actor, workspace, repository).Scan(&granted); err != nil {
				return errors.New("Pub reader grant could not be checked")
			}
			if !granted {
				return repositories.ErrForbidden
			}
			return read(tx, actor)
		})
	} else {
		err = s.repositories.WithPersonalReadTokenTransaction(ctx, token, workspace, repository, read)
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}
