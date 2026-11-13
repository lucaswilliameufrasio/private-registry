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
CREATE FUNCTION registry_npm_tag_grant_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'npm tag grant history is immutable';
    END IF;
    IF NEW.grant_id IS DISTINCT FROM OLD.grant_id OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.repository_id IS DISTINCT FROM OLD.repository_id OR NEW.repository_format IS DISTINCT FROM OLD.repository_format OR NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.granted_by IS DISTINCT FROM OLD.granted_by OR NEW.granted_at IS DISTINCT FROM OLD.granted_at OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
        RAISE EXCEPTION 'npm tag grant identity and revocation are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_npm_tag_grant_immutable BEFORE UPDATE OR DELETE ON registry_npm_tag_grants FOR EACH ROW EXECUTE FUNCTION registry_npm_tag_grant_immutable();
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION registry_npm_tag_membership_inactive() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status = 'active' AND NEW.status <> 'active' THEN
        UPDATE registry_npm_tag_grants SET revoked_at = NEW.updated_at WHERE workspace_id = NEW.workspace_id AND user_id = NEW.user_id AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_npm_tag_membership_inactive AFTER UPDATE OF status ON registry_workspace_memberships FOR EACH ROW EXECUTE FUNCTION registry_npm_tag_membership_inactive();
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION registry_npm_tag_user_inactive() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status = 'active' AND NEW.status <> 'active' THEN
        UPDATE registry_npm_tag_grants SET revoked_at = NEW.updated_at WHERE user_id = NEW.user_id AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_npm_tag_user_inactive AFTER UPDATE OF status ON registry_users FOR EACH ROW EXECUTE FUNCTION registry_npm_tag_user_inactive();
-- +goose StatementEnd
CREATE TABLE registry_npm_dist_tags (
    package_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    tag TEXT NOT NULL CHECK (length(tag) BETWEEN 1 AND 128),
    npm_version_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
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
    revision BIGINT NOT NULL CHECK (revision > 0),
    action TEXT NOT NULL CHECK (action IN ('set', 'removed')),
    actor_user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    grant_id TEXT NOT NULL REFERENCES registry_npm_tag_grants (grant_id) ON DELETE RESTRICT,
    occurred_at TEXT NOT NULL,
    UNIQUE (package_id, tag, revision),
    FOREIGN KEY (npm_version_id, package_id, workspace_id, repository_id) REFERENCES registry_npm_versions (npm_version_id, package_id, workspace_id, repository_id) ON DELETE RESTRICT
);
-- +goose StatementBegin
CREATE FUNCTION registry_npm_tag_event_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'npm tag history is immutable';
END;
$$;
CREATE TRIGGER registry_npm_tag_event_immutable BEFORE UPDATE OR DELETE ON registry_npm_tag_events FOR EACH ROW EXECUTE FUNCTION registry_npm_tag_event_immutable();
-- +goose StatementEnd
-- +goose Down
-- Forward-only: tag decisions and grant history must not be discarded.
