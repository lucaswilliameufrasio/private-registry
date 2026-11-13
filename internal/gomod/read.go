package gomod

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"sort"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	modulezip "golang.org/x/mod/zip"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

const maxListedVersions = 10000

type Version struct {
	Info    VersionInfo
	Mod     []byte
	ZipKey  storage.ObjectKey
	ZipSize int64
}

func (s *Service) authorizeRead(ctx context.Context, actorID, workspaceID, repositoryID, modulePath string) error {
	if s == nil || ctx == nil || !canonicalID(actorID) || !canonicalID(workspaceID) || !canonicalID(repositoryID) || len(modulePath) > 1024 || module.CheckPath(modulePath) != nil {
		return ErrModuleUnavailable
	}
	allowed, err := s.repositories.HasRepositoryGrant(ctx, actorID, workspaceID, repositoryID, repositories.GrantReader)
	if err != nil {
		return err
	}
	if !allowed {
		return repositories.ErrForbidden
	}
	return repositories.RequireFormat(ctx, s.db, s.driver, workspaceID, repositoryID, repositories.FormatGo)
}

// ListVersions returns canonical tagged versions, excluding pseudo-versions as
// required by GOPROXY list semantics. It refuses unbounded catalogs.
func (s *Service) ListVersions(ctx context.Context, actorID, workspaceID, repositoryID, modulePath string) ([]string, error) {
	if err := s.authorizeRead(ctx, actorID, workspaceID, repositoryID, modulePath); err != nil {
		return nil, err
	}
	query := `SELECT version FROM registry_go_module_versions WHERE workspace_id = ` + s.bind(1) + ` AND repository_id = ` + s.bind(2) + ` AND module_path = ` + s.bind(3) + ` ORDER BY version LIMIT ` + s.bind(4)
	rows, err := s.db.QueryContext(ctx, query, workspaceID, repositoryID, modulePath, maxListedVersions+1)
	if err != nil {
		return nil, errors.New("Go module versions could not be listed")
	}
	defer rows.Close()
	versions := make([]string, 0)
	count := 0
	for rows.Next() {
		count++
		if count > maxListedVersions {
			return nil, errors.New("Go module version listing exceeds its limit")
		}
		var version string
		if err := rows.Scan(&version); err != nil || module.CanonicalVersion(version) != version || module.Check(modulePath, version) != nil {
			return nil, errors.New("stored Go module version is invalid")
		}
		if !module.IsPseudoVersion(version) {
			versions = append(versions, version)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("Go module versions could not be read")
	}
	if count == 0 {
		return nil, ErrModuleUnavailable
	}
	sort.Slice(versions, func(i, j int) bool { return semver.Compare(versions[i], versions[j]) < 0 })
	return versions, nil
}

// Latest selects the highest stable version if one exists, otherwise the
// highest prerelease or pseudo-version, without contacting any upstream VCS.
func (s *Service) Latest(ctx context.Context, actorID, workspaceID, repositoryID, modulePath string) (VersionInfo, error) {
	if err := s.authorizeRead(ctx, actorID, workspaceID, repositoryID, modulePath); err != nil {
		return VersionInfo{}, err
	}
	query := `SELECT version, source_time FROM registry_go_module_versions WHERE workspace_id = ` + s.bind(1) + ` AND repository_id = ` + s.bind(2) + ` AND module_path = ` + s.bind(3) + ` LIMIT ` + s.bind(4)
	rows, err := s.db.QueryContext(ctx, query, workspaceID, repositoryID, modulePath, maxListedVersions+1)
	if err != nil {
		return VersionInfo{}, errors.New("Go module latest version could not be read")
	}
	defer rows.Close()
	var latest VersionInfo
	stable := false
	count := 0
	for rows.Next() {
		count++
		if count > maxListedVersions {
			return VersionInfo{}, errors.New("Go module version listing exceeds its limit")
		}
		var version, sourceTime string
		if err := rows.Scan(&version, &sourceTime); err != nil {
			return VersionInfo{}, errors.New("stored Go module version is invalid")
		}
		timestamp, err := time.Parse(time.RFC3339Nano, sourceTime)
		if err != nil {
			return VersionInfo{}, errors.New("stored Go module timestamp is invalid")
		}
		info, err := NewVersionInfo(modulePath, version, timestamp)
		if err != nil {
			return VersionInfo{}, errors.New("stored Go module version is invalid")
		}
		candidateStable := semver.Prerelease(version) == ""
		if latest.Version == "" || (candidateStable && !stable) || (candidateStable == stable && semver.Compare(version, latest.Version) > 0) {
			latest = info
			stable = candidateStable
		}
	}
	if err := rows.Err(); err != nil {
		return VersionInfo{}, errors.New("Go module versions could not be read")
	}
	if latest.Version == "" {
		return VersionInfo{}, ErrModuleUnavailable
	}
	return latest, nil
}

// GetVersion verifies the current reader grant before reading catalog metadata.
func (s *Service) GetVersion(ctx context.Context, actorID, workspaceID, repositoryID, modulePath, version string) (Version, error) {
	if err := s.authorizeRead(ctx, actorID, workspaceID, repositoryID, modulePath); err != nil {
		return Version{}, err
	}
	if len(version) > 200 || module.CanonicalVersion(version) != version || module.Check(modulePath, version) != nil {
		return Version{}, ErrModuleUnavailable
	}
	query := `SELECT mod_bytes, zip_sha256, zip_size, source_time FROM registry_go_module_versions WHERE workspace_id = ` + s.bind(1) + ` AND repository_id = ` + s.bind(2) + ` AND module_path = ` + s.bind(3) + ` AND version = ` + s.bind(4)
	var result Version
	var digest, timestamp string
	if err := s.db.QueryRowContext(ctx, query, workspaceID, repositoryID, modulePath, version).Scan(&result.Mod, &digest, &result.ZipSize, &timestamp); errors.Is(err, sql.ErrNoRows) {
		return Version{}, ErrModuleUnavailable
	} else if err != nil {
		return Version{}, errors.New("Go module metadata could not be read")
	}
	timeValue, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return Version{}, errors.New("stored Go module timestamp is invalid")
	}
	result.Info, err = NewVersionInfo(modulePath, version, timeValue)
	if err != nil || len(result.Mod) < 1 || len(result.Mod) > modulezip.MaxGoMod || result.ZipSize < 1 || result.ZipSize > modulezip.MaxZipFile {
		return Version{}, errors.New("stored Go module metadata is invalid")
	}
	result.ZipKey, err = storage.NewObjectKey(workspaceID, digest)
	if err != nil || result.ZipKey.SHA256 != digest {
		return Version{}, errors.New("stored Go module object key is invalid")
	}
	return result, nil
}

// OpenZip authorizes and resolves the version before touching object storage.
func (s *Service) OpenZip(ctx context.Context, actorID, workspaceID, repositoryID, modulePath, version string) (io.ReadCloser, int64, error) {
	resolved, err := s.GetVersion(ctx, actorID, workspaceID, repositoryID, modulePath, version)
	if err != nil {
		return nil, 0, err
	}
	reader, info, err := s.objects.Open(ctx, resolved.ZipKey)
	if err != nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, 0, errors.New("Go module archive could not be opened")
	}
	if info.Key != resolved.ZipKey || info.Size != resolved.ZipSize {
		_ = reader.Close()
		return nil, 0, errors.New("stored Go module archive metadata is invalid")
	}
	return reader, info.Size, nil
}
