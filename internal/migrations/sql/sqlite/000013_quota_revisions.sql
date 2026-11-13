-- +goose Up
ALTER TABLE registry_workspaces ADD COLUMN logical_quota_revision INTEGER NOT NULL DEFAULT 0 CHECK (logical_quota_revision >= 0);
ALTER TABLE registry_repositories ADD COLUMN logical_quota_revision INTEGER NOT NULL DEFAULT 0 CHECK (logical_quota_revision >= 0);

-- +goose Down
-- Forward-only: stale policy writes must not become valid after rollback.
