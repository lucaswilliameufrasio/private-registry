-- +goose Up
CREATE TABLE registry_oci_policies (
    repository_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'oci' CHECK (repository_format = 'oci'),
    immutable_tags INTEGER NOT NULL DEFAULT 0 CHECK (immutable_tags IN (0, 1)),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    updated_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT
);

-- +goose Down
-- Forward-only: publication policy history must not be discarded.
