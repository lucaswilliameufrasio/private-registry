package artifacts

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"time"
)

var publicSlugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ResolvePublicFile returns only a published file from an explicitly public,
// active repository. Private, malformed and missing resources are equivalent.
func (s *Service) ResolvePublicFile(ctx context.Context, workspaceSlug, repositorySlug, collection, version, filePath string) (File, error) {
	file, _, err := s.resolvePublicFile(ctx, workspaceSlug, repositorySlug, collection, version, filePath)
	return file, err
}

// OpenPublicFile repeats visibility and publication checks before opening any
// bytes. A response that has already started may outlive a visibility change.
func (s *Service) OpenPublicFile(ctx context.Context, workspaceSlug, repositorySlug, collection, version, filePath, expectedFileID string, offset, length int64) (OpenedFile, error) {
	file, workspaceID, err := s.resolvePublicFile(ctx, workspaceSlug, repositorySlug, collection, version, filePath)
	if err != nil {
		return OpenedFile{}, err
	}
	if file.ID != expectedFileID {
		return OpenedFile{}, ErrArtifactNotFound
	}
	return s.openObject(ctx, workspaceID, file, offset, length)
}

func (s *Service) resolvePublicFile(ctx context.Context, workspaceSlug, repositorySlug, collection, version, filePath string) (File, string, error) {
	if s == nil || s.db == nil || ctx == nil {
		return File{}, "", errors.New("public artifact service is unavailable")
	}
	if !publicSlugPattern.MatchString(workspaceSlug) || !publicSlugPattern.MatchString(repositorySlug) ||
		!collectionNamePattern.MatchString(collection) || !versionLabelPattern.MatchString(version) || validateArtifactPath(filePath) != nil {
		return File{}, "", ErrArtifactNotFound
	}
	query := `SELECT f.artifact_file_id, f.path, f.content_type, f.size_bytes, f.sha256, f.created_by, f.created_at, f.workspace_id
		FROM registry_generic_artifact_files f
		JOIN registry_generic_artifact_versions v ON v.artifact_version_id = f.artifact_version_id AND v.workspace_id = f.workspace_id AND v.repository_id = f.repository_id
		JOIN registry_repositories r ON r.repository_id = f.repository_id AND r.workspace_id = f.workspace_id
		JOIN registry_workspaces w ON w.workspace_id = f.workspace_id
		WHERE w.slug = ` + bind(s.driver, 1) + ` AND w.status = 'active' AND r.slug = ` + bind(s.driver, 2) + ` AND r.status = 'active'
		AND r.visibility IN ('listed', 'unlisted') AND v.collection_name = ` + bind(s.driver, 3) + ` AND v.version_label = ` + bind(s.driver, 4) + `
		AND v.status = 'published' AND f.path = ` + bind(s.driver, 5)
	var file File
	var createdAt, workspaceID string
	if err := s.db.QueryRowContext(ctx, query, workspaceSlug, repositorySlug, collection, version, filePath).Scan(
		&file.ID, &file.Path, &file.ContentType, &file.Size, &file.SHA256, &file.CreatedBy, &createdAt, &workspaceID,
	); errors.Is(err, sql.ErrNoRows) {
		return File{}, "", ErrArtifactNotFound
	} else if err != nil {
		return File{}, "", errors.New("public artifact metadata could not be read")
	}
	if file.Size < 0 || !sha256Pattern.MatchString(file.SHA256) {
		return File{}, "", ErrArtifactIntegrity
	}
	created, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return File{}, "", errors.New("public artifact metadata is invalid")
	}
	file.CreatedAt = created
	return file, workspaceID, nil
}
