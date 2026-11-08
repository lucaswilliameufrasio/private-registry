package npm

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"private-registry/internal/repositories"
)

const maxPackumentVersions = 10000
const maxPackumentBytes = 16 << 20
const maxPackumentTags = 1000

type PublishedVersion struct {
	Version   string
	Manifest  json.RawMessage
	Integrity string
}

type PublishedPackage struct {
	Name     string
	Versions []PublishedVersion
	Tags     map[string]string
}

// ReadPublishedPackageWithToken returns bounded published metadata only, after
// checking the token's original reader grant. It does not construct HTTP URLs,
// expose pending receipts, contact an upstream, or grant tag management.
func (s *ReservationService) ReadPublishedPackageWithToken(ctx context.Context, token, workspace, repository, name string) (PublishedPackage, error) {
	if s == nil || ctx == nil || ValidatePackageName(name) != nil {
		return PublishedPackage{}, ErrPackageUnavailable
	}
	result := PublishedPackage{Name: name, Versions: []PublishedVersion{}, Tags: make(map[string]string)}
	err := s.repositories.WithPersonalReadTokenTransaction(ctx, token, workspace, repository, func(tx *sql.Tx, _ string) error {
		if err := repositories.RequireFormat(ctx, tx, s.driver, workspace, repository, repositories.FormatNPM); err != nil {
			return err
		}
		query := `SELECT v.version_identity, v.manifest, v.integrity FROM registry_npm_packages p JOIN registry_npm_versions v ON v.package_id = p.package_id AND v.workspace_id = p.workspace_id AND v.repository_id = p.repository_id JOIN registry_npm_publications pub ON pub.npm_version_id = v.npm_version_id AND pub.workspace_id = v.workspace_id AND pub.repository_id = v.repository_id WHERE p.workspace_id = ` + s.bind(1) + ` AND p.repository_id = ` + s.bind(2) + ` AND p.name = ` + s.bind(3) + ` ORDER BY v.version_identity LIMIT ` + s.bind(4)
		rows, err := tx.QueryContext(ctx, query, workspace, repository, name, maxPackumentVersions+1)
		if err != nil {
			return errors.New("npm published versions could not be read")
		}
		total := 0
		for rows.Next() {
			if len(result.Versions) == maxPackumentVersions {
				_ = rows.Close()
				return errors.New("npm package exceeds version limit")
			}
			var item PublishedVersion
			var manifest string
			if err := rows.Scan(&item.Version, &manifest, &item.Integrity); err != nil || !json.Valid([]byte(manifest)) {
				_ = rows.Close()
				return errors.New("npm published metadata is invalid")
			}
			if len(manifest) > maxPackumentBytes-total {
				_ = rows.Close()
				return errors.New("npm package exceeds metadata limit")
			}
			total += len(manifest)
			item.Manifest = json.RawMessage(manifest)
			result.Versions = append(result.Versions, item)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return errors.New("npm published versions could not be iterated")
		}
		if err := rows.Close(); err != nil {
			return errors.New("npm published versions could not be closed")
		}
		if len(result.Versions) == 0 {
			return ErrPackageUnavailable
		}
		query = `SELECT t.tag, v.version_identity FROM registry_npm_dist_tags t JOIN registry_npm_packages p ON p.package_id = t.package_id AND p.workspace_id = t.workspace_id AND p.repository_id = t.repository_id JOIN registry_npm_versions v ON v.npm_version_id = t.npm_version_id AND v.package_id = t.package_id AND v.workspace_id = t.workspace_id AND v.repository_id = t.repository_id JOIN registry_npm_publications pub ON pub.npm_version_id = v.npm_version_id AND pub.workspace_id = v.workspace_id AND pub.repository_id = v.repository_id WHERE t.workspace_id = ` + s.bind(1) + ` AND t.repository_id = ` + s.bind(2) + ` AND p.name = ` + s.bind(3) + ` AND t.active = 1 ORDER BY t.tag LIMIT ` + s.bind(4)
		rows, err = tx.QueryContext(ctx, query, workspace, repository, name, maxPackumentTags+1)
		if err != nil {
			return errors.New("npm tags could not be read")
		}
		defer rows.Close()
		for rows.Next() {
			if len(result.Tags) == maxPackumentTags {
				return errors.New("npm package exceeds tag limit")
			}
			var tag, version string
			if err := rows.Scan(&tag, &version); err != nil || !validTag(tag) {
				return errors.New("npm tag metadata is invalid")
			}
			result.Tags[tag] = version
		}
		if err := rows.Err(); err != nil {
			return errors.New("npm tags could not be iterated")
		}
		return nil
	})
	if err != nil {
		return PublishedPackage{}, err
	}
	return result, nil
}
