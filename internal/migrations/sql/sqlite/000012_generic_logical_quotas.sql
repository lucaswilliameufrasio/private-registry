-- +goose Up
ALTER TABLE registry_workspaces ADD COLUMN logical_quota_bytes INTEGER CHECK (logical_quota_bytes IS NULL OR logical_quota_bytes >= 0);
ALTER TABLE registry_repositories ADD COLUMN logical_quota_bytes INTEGER CHECK (logical_quota_bytes IS NULL OR logical_quota_bytes >= 0);
CREATE INDEX registry_generic_upload_quota_workspace_idx ON registry_generic_upload_sessions (workspace_id, status);
CREATE INDEX registry_generic_upload_quota_repository_idx ON registry_generic_upload_sessions (workspace_id, repository_id, status);

-- +goose Down
-- Forward-only: quota configuration must not be silently discarded.
