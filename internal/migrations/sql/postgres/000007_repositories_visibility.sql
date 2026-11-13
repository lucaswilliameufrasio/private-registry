-- +goose Up
ALTER TABLE registry_installation
    ADD COLUMN repository_visibility_policy TEXT NOT NULL DEFAULT 'private_only'
        CHECK (repository_visibility_policy IN ('private_only', 'private_and_unlisted', 'all'));

CREATE TABLE registry_repositories (
    repository_id TEXT PRIMARY KEY CHECK (length(repository_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES registry_workspaces (workspace_id) ON DELETE RESTRICT,
    slug TEXT NOT NULL CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    display_name TEXT NOT NULL CHECK (length(trim(display_name)) BETWEEN 1 AND 200),
    visibility TEXT NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('private', 'unlisted', 'listed')),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'deletion_pending', 'deleted')),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    UNIQUE (workspace_id, slug),
    UNIQUE (repository_id, workspace_id)
);

CREATE INDEX registry_repositories_workspace_status_idx
    ON registry_repositories (workspace_id, status, repository_id);

-- +goose StatementBegin
CREATE FUNCTION registry_repositories_identity_is_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.workspace_id <> OLD.workspace_id OR NEW.slug <> OLD.slug THEN
        RAISE EXCEPTION 'repository workspace and slug are immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER registry_repositories_identity_immutable
BEFORE UPDATE OF workspace_id, slug ON registry_repositories
FOR EACH ROW EXECUTE FUNCTION registry_repositories_identity_is_immutable();

-- +goose Down
-- Forward-only: repository identities and visibility policy must not be dropped automatically.
