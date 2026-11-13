package pub

import (
	"context"
	"database/sql"
	"errors"
	"io"

	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

var ErrPackageUnavailable = errors.New("pub package is unavailable")

// OpenPublishedArchiveWithToken checks the original reader grant before
// resolving or opening storage. Already delivered bytes cannot be retracted.
// This internal primitive does not expose an HTTP route or a Pub HTTP route.
func (s *ReceiptService) OpenPublishedArchiveWithToken(ctx context.Context, token, workspace, repository, name, version string) (io.ReadCloser, int64, error) {
	if s == nil || ctx == nil || ValidateName(name) != nil {
		return nil, 0, ErrPackageUnavailable
	}
	_, err := VersionIdentity(version)
	if err != nil {
		return nil, 0, ErrPackageUnavailable
	}
	var digest string
	var size int64
	err = s.repositories.WithPersonalReadTokenTransaction(ctx, token, workspace, repository, func(tx *sql.Tx, _ string) error {
		if err := repositories.RequireFormat(ctx, tx, s.driver, workspace, repository, repositories.FormatPub); err != nil {
			return err
		}
		query := `SELECT v.tarball_sha256, v.tarball_size FROM registry_pub_versions v JOIN registry_pub_packages p ON p.package_id = v.package_id AND p.workspace_id = v.workspace_id AND p.repository_id = v.repository_id JOIN registry_pub_publications np ON np.pub_version_id = v.pub_version_id AND np.workspace_id = v.workspace_id AND np.repository_id = v.repository_id WHERE v.workspace_id = ` + s.bind(1) + ` AND v.repository_id = ` + s.bind(2) + ` AND p.name = ` + s.bind(3) + ` AND v.version = ` + s.bind(4)
		if err := tx.QueryRowContext(ctx, query, workspace, repository, name, version).Scan(&digest, &size); errors.Is(err, sql.ErrNoRows) {
			return ErrPackageUnavailable
		} else if err != nil {
			return errors.New("pub archive metadata could not be read")
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	key, err := storage.NewObjectKey(workspace, digest)
	if err != nil || key.SHA256 != digest || size < 1 || size > s.options.Limits.MaxCompressedBytes {
		return nil, 0, errors.New("pub archive metadata is invalid")
	}
	reader, info, err := s.objects.Open(ctx, key)
	if err != nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, 0, errors.New("pub archive could not be opened")
	}
	if info.Key != key || info.Size != size {
		_ = reader.Close()
		return nil, 0, errors.New("pub archive metadata differs")
	}
	return reader, size, nil
}
