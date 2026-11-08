-- +goose Up
-- The migration runner supplies a dedicated connection with these pragmas;
-- the rebuild and version record remain in one Goose transaction.
CREATE TEMP TABLE registry_format_migration_guard (n INTEGER NOT NULL CHECK (n = 0));
INSERT INTO registry_format_migration_guard
SELECT CASE WHEN (SELECT foreign_keys FROM pragma_foreign_keys) = 0
                 AND (SELECT legacy_alter_table FROM pragma_legacy_alter_table) = 1
            THEN 0 ELSE 1 END;

ALTER TABLE registry_repositories RENAME TO registry_repositories_before_format33;
CREATE TABLE registry_repositories (
    repository_id TEXT PRIMARY KEY CHECK (length(repository_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES registry_workspaces (workspace_id) ON DELETE RESTRICT,
    slug TEXT NOT NULL CHECK (
        length(slug) BETWEEN 1 AND 63 AND slug = lower(slug)
        AND slug NOT GLOB '*[^a-z0-9-]*'
        AND substr(slug, 1, 1) GLOB '[a-z0-9]'
        AND substr(slug, -1, 1) GLOB '[a-z0-9]'
    ),
    display_name TEXT NOT NULL CHECK (length(trim(display_name)) BETWEEN 1 AND 200),
    visibility TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'unlisted', 'listed')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deletion_pending', 'deleted')),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    logical_quota_bytes INTEGER CHECK (logical_quota_bytes IS NULL OR logical_quota_bytes >= 0),
    logical_quota_revision INTEGER NOT NULL DEFAULT 0 CHECK (logical_quota_revision >= 0),
    format TEXT NOT NULL DEFAULT 'generic' CHECK (format IN ('generic', 'go', 'cargo', 'npm', 'pub')),
    review_required INTEGER NOT NULL DEFAULT 0 CHECK (review_required IN (0, 1)),
    review_revision INTEGER NOT NULL DEFAULT 0 CHECK (review_revision >= 0),
    go_namespace_mode TEXT NOT NULL DEFAULT 'private_all' CHECK (go_namespace_mode IN ('private_all', 'private_prefixes')),
    go_namespace_revision INTEGER NOT NULL DEFAULT 0 CHECK (go_namespace_revision >= 0),
    UNIQUE (workspace_id, slug),
    UNIQUE (repository_id, workspace_id)
);
INSERT INTO registry_repositories (
    repository_id, workspace_id, slug, display_name, visibility, status,
    created_by, created_at, updated_at, deleted_at, logical_quota_bytes,
    logical_quota_revision, format, review_required, review_revision,
    go_namespace_mode, go_namespace_revision
)
SELECT repository_id, workspace_id, slug, display_name, visibility, status,
       created_by, created_at, updated_at, deleted_at, logical_quota_bytes,
       logical_quota_revision, format, review_required, review_revision,
       go_namespace_mode, go_namespace_revision
FROM registry_repositories_before_format33;
DROP TABLE registry_repositories_before_format33;

CREATE INDEX registry_repositories_workspace_status_idx ON registry_repositories (workspace_id, status, repository_id);
CREATE UNIQUE INDEX registry_repository_format_identity_idx ON registry_repositories (repository_id, workspace_id, format);

-- +goose StatementBegin
CREATE TRIGGER registry_repositories_identity_immutable
BEFORE UPDATE OF workspace_id, slug ON registry_repositories
WHEN NEW.workspace_id <> OLD.workspace_id OR NEW.slug <> OLD.slug
BEGIN
    SELECT RAISE(ABORT, 'repository workspace and slug are immutable');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER registry_repository_format_immutable BEFORE UPDATE OF format ON registry_repositories
WHEN NEW.format <> OLD.format
BEGIN
    SELECT RAISE(ABORT, 'repository format is immutable');
END;
-- +goose StatementEnd

INSERT INTO registry_format_migration_guard SELECT count(*) FROM pragma_foreign_key_check;
DROP TABLE registry_format_migration_guard;

-- +goose Down
-- Forward-only: repository identities and format assignments must not be discarded.
