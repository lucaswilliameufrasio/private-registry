package npm

import (
	"context"
	"database/sql"
	"errors"
	"io"

	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

var ErrPackageUnavailable = errors.New("npm package is unavailable")

// OpenPublishedArchiveWithToken checks the original reader grant before
// resolving or opening storage. Already delivered bytes cannot be retracted.
// This internal primitive does not expose an HTTP route or an npm packument.
func (s *ReceiptService) OpenPublishedArchiveWithToken(ctx context.Context, token, workspace, repository, name, version string) (io.ReadCloser, int64, error) {
	if s == nil || ctx == nil || ValidatePackageName(name) != nil {
		return nil, 0, ErrPackageUnavailable
	}
	versionKey, err := VersionIdentity(version)
	if err != nil || versionKey != version {
		return nil, 0, ErrPackageUnavailable
	}
	var digest string
	var size int64
	err = s.repositories.WithPersonalReadTokenTransaction(ctx, token, workspace, repository, func(tx *sql.Tx, _ string) error {
		if err := repositories.RequireFormat(ctx, tx, s.driver, workspace, repository, repositories.FormatNPM); err != nil {
			return err
		}
		query := `SELECT v.tarball_sha256, v.tarball_size FROM registry_npm_versions v JOIN registry_npm_packages p ON p.package_id = v.package_id AND p.workspace_id = v.workspace_id AND p.repository_id = v.repository_id JOIN registry_npm_publications np ON np.npm_version_id = v.npm_version_id AND np.workspace_id = v.workspace_id AND np.repository_id = v.repository_id WHERE v.workspace_id = ` + s.bind(1) + ` AND v.repository_id = ` + s.bind(2) + ` AND p.name = ` + s.bind(3) + ` AND v.version_identity = ` + s.bind(4)
		if err := tx.QueryRowContext(ctx, query, workspace, repository, name, versionKey).Scan(&digest, &size); errors.Is(err, sql.ErrNoRows) {
			return ErrPackageUnavailable
		} else if err != nil {
			return errors.New("npm archive metadata could not be read")
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	key, err := storage.NewObjectKey(workspace, digest)
	if err != nil || key.SHA256 != digest || size < 1 || size > s.options.Limits.MaxCompressedBytes {
		return nil, 0, errors.New("npm archive metadata is invalid")
	}
	reader, info, err := s.objects.Open(ctx, key)
	if err != nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, 0, errors.New("npm archive could not be opened")
	}
	if info.Key != key || info.Size != size {
		_ = reader.Close()
		return nil, 0, errors.New("npm archive metadata differs")
	}
	return reader, size, nil
}
