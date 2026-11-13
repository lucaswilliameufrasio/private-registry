-- +goose Up
CREATE UNIQUE INDEX registry_npm_version_package_scope_idx ON registry_npm_versions (npm_version_id, package_id, workspace_id, repository_id);
CREATE TABLE registry_npm_tag_grants (
    grant_id TEXT PRIMARY KEY CHECK (length(grant_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'npm' CHECK (repository_format = 'npm'),
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX registry_npm_tag_grant_active_idx ON registry_npm_tag_grants (repository_id, user_id) WHERE revoked_at IS NULL;
-- +goose StatementBegin
CREATE TRIGGER registry_npm_tag_grant_immutable BEFORE UPDATE ON registry_npm_tag_grants
WHEN NEW.grant_id <> OLD.grant_id OR NEW.workspace_id <> OLD.workspace_id OR NEW.repository_id <> OLD.repository_id OR NEW.repository_format <> OLD.repository_format OR NEW.user_id <> OLD.user_id OR NEW.granted_by <> OLD.granted_by OR NEW.granted_at <> OLD.granted_at OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
BEGIN
    SELECT RAISE(ABORT, 'npm tag grant identity and revocation are immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_npm_tag_grant_no_delete BEFORE DELETE ON registry_npm_tag_grants
BEGIN
    SELECT RAISE(ABORT, 'npm tag grant history is immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_npm_tag_membership_inactive AFTER UPDATE OF status ON registry_workspace_memberships
WHEN OLD.status = 'active' AND NEW.status <> 'active'
BEGIN
    UPDATE registry_npm_tag_grants SET revoked_at = NEW.updated_at WHERE workspace_id = NEW.workspace_id AND user_id = NEW.user_id AND revoked_at IS NULL;
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_npm_tag_user_inactive AFTER UPDATE OF status ON registry_users
WHEN OLD.status = 'active' AND NEW.status <> 'active'
BEGIN
    UPDATE registry_npm_tag_grants SET revoked_at = NEW.updated_at WHERE user_id = NEW.user_id AND revoked_at IS NULL;
END;
-- +goose StatementEnd
CREATE TABLE registry_npm_dist_tags (
    package_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    tag TEXT NOT NULL CHECK (length(tag) BETWEEN 1 AND 128),
    npm_version_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    PRIMARY KEY (package_id, tag),
    FOREIGN KEY (package_id, workspace_id, repository_id) REFERENCES registry_npm_packages (package_id, workspace_id, repository_id) ON DELETE RESTRICT,
    FOREIGN KEY (npm_version_id, package_id, workspace_id, repository_id) REFERENCES registry_npm_versions (npm_version_id, package_id, workspace_id, repository_id) ON DELETE RESTRICT
);
CREATE TABLE registry_npm_tag_events (
    event_id TEXT PRIMARY KEY CHECK (length(event_id) = 36),
    package_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    tag TEXT NOT NULL CHECK (length(tag) BETWEEN 1 AND 128),
    npm_version_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    action TEXT NOT NULL CHECK (action IN ('set', 'removed')),
    actor_user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    grant_id TEXT NOT NULL REFERENCES registry_npm_tag_grants (grant_id) ON DELETE RESTRICT,
    occurred_at TEXT NOT NULL,
    UNIQUE (package_id, tag, revision),
    FOREIGN KEY (npm_version_id, package_id, workspace_id, repository_id) REFERENCES registry_npm_versions (npm_version_id, package_id, workspace_id, repository_id) ON DELETE RESTRICT
);
-- +goose StatementBegin
CREATE TRIGGER registry_npm_tag_event_no_update BEFORE UPDATE ON registry_npm_tag_events BEGIN SELECT RAISE(ABORT, 'npm tag history is immutable'); END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_npm_tag_event_no_delete BEFORE DELETE ON registry_npm_tag_events BEGIN SELECT RAISE(ABORT, 'npm tag history is immutable'); END;
-- +goose StatementEnd
-- +goose Down
-- Forward-only: tag decisions and grant history must not be discarded.
