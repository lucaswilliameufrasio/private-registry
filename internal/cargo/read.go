package cargo

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

var ErrPackageUnavailable = errors.New("Cargo package is unavailable")

const maxIndexBytes = 16 << 20
const maxIndexVersions = 10000

// ReadSparseIndex lists only published versions, after an explicit reader
// grant check. It never falls back to an upstream or exposes pending receipts.
func (s *ReservationService) ReadSparseIndex(ctx context.Context, actor, workspace, repository, name string) ([]byte, error) {
	if s == nil {
		return nil, ErrPackageUnavailable
	}
	return s.readSparseIndex(ctx, workspace, repository, name, func(operation func(*sql.Tx) error) error {
		return s.repositories.WithRepositoryGrantTransaction(ctx, actor, workspace, repository, repositories.GrantReader, operation)
	})
}

// ReadSparseIndexWithToken revalidates the exact token and its original grant
// in the same transaction that reads the published index.
func (s *ReservationService) ReadSparseIndexWithToken(ctx context.Context, token, workspace, repository, name string) ([]byte, error) {
	if s == nil {
		return nil, ErrPackageUnavailable
	}
	return s.readSparseIndex(ctx, workspace, repository, name, func(operation func(*sql.Tx) error) error {
		return s.repositories.WithPersonalReadTokenTransaction(ctx, token, workspace, repository, func(tx *sql.Tx, _ string) error {
			return operation(tx)
		})
	})
}

func (s *ReservationService) readSparseIndex(ctx context.Context, workspace, repository, name string, authorize func(func(*sql.Tx) error) error) ([]byte, error) {
	if s == nil || ctx == nil {
		return nil, ErrPackageUnavailable
	}
	identity, err := NameIdentity(name)
	if err != nil {
		return nil, ErrPackageUnavailable
	}
	var output bytes.Buffer
	err = authorize(func(tx *sql.Tx) error {
		if err := repositories.RequireFormat(ctx, tx, s.driver, workspace, repository, repositories.FormatCargo); err != nil {
			return err
		}
		query := `SELECT v.index_entry, v.yanked FROM registry_cargo_versions v JOIN registry_cargo_packages p ON p.package_id = v.package_id AND p.workspace_id = v.workspace_id AND p.repository_id = v.repository_id JOIN registry_cargo_publications cp ON cp.cargo_version_id = v.cargo_version_id AND cp.workspace_id = v.workspace_id AND cp.repository_id = v.repository_id WHERE v.workspace_id = ` + s.bind(1) + ` AND v.repository_id = ` + s.bind(2) + ` AND p.name_identity = ` + s.bind(3) + ` AND lower(p.name) = ` + s.bind(4) + ` ORDER BY v.version_identity LIMIT ` + s.bind(5)
		rows, err := tx.QueryContext(ctx, query, workspace, repository, identity, strings.ToLower(name), maxIndexVersions+1)
		if err != nil {
			return errors.New("Cargo sparse index could not be read")
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			count++
			if count > maxIndexVersions {
				return errors.New("Cargo sparse index exceeds its version limit")
			}
			var entry string
			var yanked int
			if err := rows.Scan(&entry, &yanked); err != nil || (yanked != 0 && yanked != 1) {
				return errors.New("Cargo sparse index entry is invalid")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(entry), &fields); err != nil || fields == nil {
				return errors.New("Cargo sparse index entry is invalid")
			}
			if yanked == 1 {
				fields["yanked"] = json.RawMessage("true")
			} else {
				fields["yanked"] = json.RawMessage("false")
			}
			encoded, err := json.Marshal(fields)
			if err != nil || len(encoded)+1 > maxIndexBytes-output.Len() {
				return errors.New("Cargo sparse index exceeds its byte limit")
			}
			output.Write(encoded)
			output.WriteByte('\n')
		}
		if err := rows.Err(); err != nil {
			return errors.New("Cargo sparse index entries could not be iterated")
		}
		if count == 0 {
			return ErrPackageUnavailable
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// OpenPublishedArchive authorizes before resolving the published object. An
// already opened stream cannot retract bytes after a later grant revocation.
func (s *ReceiptService) OpenPublishedArchive(ctx context.Context, actor, workspace, repository, name, version string) (io.ReadCloser, int64, error) {
	if s == nil {
		return nil, 0, ErrPackageUnavailable
	}
	return s.openPublishedArchive(ctx, workspace, repository, name, version, func(operation func(*sql.Tx) error) error {
		return s.repositories.WithRepositoryGrantTransaction(ctx, actor, workspace, repository, repositories.GrantReader, operation)
	})
}

// OpenPublishedArchiveWithToken validates the original grant of the read token
// while resolving metadata. An already opened stream cannot retract bytes.
func (s *ReceiptService) OpenPublishedArchiveWithToken(ctx context.Context, token, workspace, repository, name, version string) (io.ReadCloser, int64, error) {
	if s == nil {
		return nil, 0, ErrPackageUnavailable
	}
	return s.openPublishedArchive(ctx, workspace, repository, name, version, func(operation func(*sql.Tx) error) error {
		return s.repositories.WithPersonalReadTokenTransaction(ctx, token, workspace, repository, func(tx *sql.Tx, _ string) error {
			return operation(tx)
		})
	})
}

func (s *ReceiptService) openPublishedArchive(ctx context.Context, workspace, repository, name, version string, authorize func(func(*sql.Tx) error) error) (io.ReadCloser, int64, error) {
	if s == nil || ctx == nil {
		return nil, 0, ErrPackageUnavailable
	}
	identity, err := NameIdentity(name)
	if err != nil {
		return nil, 0, ErrPackageUnavailable
	}
	versionKey, err := VersionIdentity(version)
	if err != nil || versionKey != version {
		return nil, 0, ErrPackageUnavailable
	}
	var digest string
	var size int64
	err = authorize(func(tx *sql.Tx) error {
		if err := repositories.RequireFormat(ctx, tx, s.driver, workspace, repository, repositories.FormatCargo); err != nil {
			return err
		}
		query := `SELECT v.archive_sha256, v.archive_size FROM registry_cargo_versions v JOIN registry_cargo_packages p ON p.package_id = v.package_id AND p.workspace_id = v.workspace_id AND p.repository_id = v.repository_id JOIN registry_cargo_publications cp ON cp.cargo_version_id = v.cargo_version_id AND cp.workspace_id = v.workspace_id AND cp.repository_id = v.repository_id WHERE v.workspace_id = ` + s.bind(1) + ` AND v.repository_id = ` + s.bind(2) + ` AND p.name_identity = ` + s.bind(3) + ` AND lower(p.name) = ` + s.bind(4) + ` AND v.version_identity = ` + s.bind(5)
		if err := tx.QueryRowContext(ctx, query, workspace, repository, identity, strings.ToLower(name), versionKey).Scan(&digest, &size); errors.Is(err, sql.ErrNoRows) {
			return ErrPackageUnavailable
		} else if err != nil {
			return errors.New("Cargo published archive metadata could not be read")
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	key, err := storage.NewObjectKey(workspace, digest)
	if err != nil || key.SHA256 != digest || size < 1 || size > s.options.Limits.MaxCompressedBytes {
		return nil, 0, errors.New("Cargo published archive metadata is invalid")
	}
	reader, info, err := s.objects.Open(ctx, key)
	if err != nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, 0, errors.New("Cargo published archive could not be opened")
	}
	if info.Key != key || info.Size != size {
		_ = reader.Close()
		return nil, 0, errors.New("Cargo published archive metadata differs")
	}
	return reader, size, nil
}
