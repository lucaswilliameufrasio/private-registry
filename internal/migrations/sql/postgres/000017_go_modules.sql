-- +goose Up
ALTER TABLE registry_repositories ADD COLUMN format TEXT NOT NULL DEFAULT 'generic'
    CHECK (format IN ('generic', 'go'));
ALTER TABLE registry_repositories ADD COLUMN review_required INTEGER NOT NULL DEFAULT 0 CHECK (review_required IN (0, 1));
ALTER TABLE registry_repositories ADD COLUMN review_revision BIGINT NOT NULL DEFAULT 0 CHECK (review_revision >= 0);
ALTER TABLE registry_repositories ADD COLUMN go_namespace_mode TEXT NOT NULL DEFAULT 'private_all' CHECK (go_namespace_mode IN ('private_all', 'private_prefixes'));
ALTER TABLE registry_repositories ADD COLUMN go_namespace_revision BIGINT NOT NULL DEFAULT 0 CHECK (go_namespace_revision >= 0);
CREATE UNIQUE INDEX registry_repository_format_identity_idx ON registry_repositories (repository_id, workspace_id, format);

CREATE TABLE registry_go_private_prefixes (
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'go' CHECK (repository_format = 'go'),
    prefix TEXT NOT NULL CHECK (length(prefix) BETWEEN 1 AND 1024),
    PRIMARY KEY (repository_id, prefix),
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT
);

-- +goose StatementBegin
CREATE FUNCTION registry_repository_format_immutable() RETURNS trigger AS $$
BEGIN
    IF NEW.format <> OLD.format THEN
        RAISE EXCEPTION 'repository format is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER registry_repository_format_immutable BEFORE UPDATE OF format ON registry_repositories
FOR EACH ROW EXECUTE FUNCTION registry_repository_format_immutable();
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION registry_generic_version_format_guard() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM registry_repositories WHERE repository_id = NEW.repository_id AND workspace_id = NEW.workspace_id AND format = 'generic') THEN
        RAISE EXCEPTION 'generic artifacts require a generic repository';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER registry_generic_version_format_guard BEFORE INSERT OR UPDATE OF repository_id, workspace_id ON registry_generic_artifact_versions
FOR EACH ROW EXECUTE FUNCTION registry_generic_version_format_guard();
-- +goose StatementEnd

CREATE TABLE registry_go_module_versions (
    module_version_id TEXT PRIMARY KEY CHECK (length(module_version_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'go' CHECK (repository_format = 'go'),
    module_path TEXT NOT NULL CHECK (length(module_path) BETWEEN 1 AND 1024),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 200),
    mod_bytes BYTEA NOT NULL CHECK (octet_length(mod_bytes) BETWEEN 1 AND 16777216),
    zip_sha256 TEXT NOT NULL CHECK (zip_sha256 ~ '^[0-9a-f]{64}$'),
    zip_size BIGINT NOT NULL CHECK (zip_size BETWEEN 1 AND 524288000),
    source_time TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT,
    UNIQUE (repository_id, module_path, version)
);
CREATE INDEX registry_go_module_lookup_idx ON registry_go_module_versions (workspace_id, repository_id, module_path, version);

CREATE TABLE registry_go_reviewer_grants (
    grant_id TEXT PRIMARY KEY CHECK (length(grant_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (repository_id, workspace_id) REFERENCES registry_repositories (repository_id, workspace_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX registry_go_reviewer_active_idx ON registry_go_reviewer_grants (repository_id, user_id) WHERE revoked_at IS NULL;

-- +goose StatementBegin
CREATE FUNCTION registry_go_reviewer_grant_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.grant_id IS DISTINCT FROM OLD.grant_id OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.repository_id IS DISTINCT FROM OLD.repository_id OR NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.granted_by IS DISTINCT FROM OLD.granted_by OR NEW.granted_at IS DISTINCT FROM OLD.granted_at OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
        RAISE EXCEPTION 'Go reviewer grant identity and revocation are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_go_reviewer_grant_immutable BEFORE UPDATE ON registry_go_reviewer_grants
FOR EACH ROW EXECUTE FUNCTION registry_go_reviewer_grant_immutable();
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION registry_go_reviewer_membership_inactive() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status = 'active' AND NEW.status <> 'active' THEN
        UPDATE registry_go_reviewer_grants SET revoked_at = NEW.updated_at WHERE workspace_id = NEW.workspace_id AND user_id = NEW.user_id AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_go_reviewer_membership_inactive AFTER UPDATE OF status ON registry_workspace_memberships
FOR EACH ROW EXECUTE FUNCTION registry_go_reviewer_membership_inactive();
-- +goose StatementEnd

CREATE TABLE registry_go_upload_sessions (
    upload_session_id TEXT PRIMARY KEY CHECK (length(upload_session_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'go' CHECK (repository_format = 'go'),
    module_path TEXT NOT NULL CHECK (length(module_path) BETWEEN 1 AND 1024),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 200),
    mod_bytes BYTEA NOT NULL CHECK (octet_length(mod_bytes) BETWEEN 1 AND 16777216),
    zip_sha256 TEXT NOT NULL CHECK (zip_sha256 ~ '^[0-9a-f]{64}$'),
    zip_size BIGINT NOT NULL CHECK (zip_size BETWEEN 1 AND 524288000),
    source_time TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('receiving', 'uploading', 'uploaded', 'published', 'expired', 'rejected')),
    upload_claim_id TEXT,
    recovery_invalidated INTEGER NOT NULL DEFAULT 0 CHECK (recovery_invalidated IN (0, 1)),
    object_verified INTEGER NOT NULL DEFAULT 0 CHECK (object_verified IN (0, 1)),
    review_hold INTEGER NOT NULL DEFAULT 0 CHECK (review_hold IN (0, 1)),
    reviewed_by TEXT REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    review_grant_id TEXT REFERENCES registry_go_reviewer_grants (grant_id) ON DELETE RESTRICT,
    review_publisher_grant_id TEXT REFERENCES registry_repository_grants (grant_id) ON DELETE RESTRICT,
    reviewed_policy_revision BIGINT,
    reviewed_at TEXT,
    published_version_id TEXT REFERENCES registry_go_module_versions (module_version_id) ON DELETE RESTRICT,
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > created_at_ms),
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT,
    CHECK ((status = 'uploading' AND upload_claim_id IS NOT NULL) OR (status <> 'uploading' AND upload_claim_id IS NULL)),
    CHECK ((status IN ('uploaded', 'published') AND object_verified = 1) OR (status = 'rejected') OR (status NOT IN ('uploaded', 'published', 'rejected') AND object_verified = 0)),
    CHECK ((status = 'published' AND published_version_id IS NOT NULL) OR (status <> 'published' AND published_version_id IS NULL)),
    CHECK ((reviewed_by IS NULL AND review_grant_id IS NULL AND review_publisher_grant_id IS NULL AND reviewed_policy_revision IS NULL AND reviewed_at IS NULL) OR (reviewed_by IS NOT NULL AND review_grant_id IS NOT NULL AND review_publisher_grant_id IS NOT NULL AND reviewed_policy_revision IS NOT NULL AND reviewed_policy_revision >= 0 AND reviewed_at IS NOT NULL))
);
CREATE UNIQUE INDEX registry_go_upload_active_identity_idx ON registry_go_upload_sessions (repository_id, module_path, version) WHERE status IN ('receiving', 'uploading', 'uploaded');
CREATE INDEX registry_go_upload_expiry_idx ON registry_go_upload_sessions (status, expires_at_ms);

-- +goose StatementBegin
CREATE FUNCTION registry_go_upload_identity_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.upload_session_id IS DISTINCT FROM OLD.upload_session_id OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.repository_id IS DISTINCT FROM OLD.repository_id OR NEW.repository_format IS DISTINCT FROM OLD.repository_format OR NEW.module_path IS DISTINCT FROM OLD.module_path OR NEW.version IS DISTINCT FROM OLD.version OR NEW.mod_bytes IS DISTINCT FROM OLD.mod_bytes OR NEW.zip_sha256 IS DISTINCT FROM OLD.zip_sha256 OR NEW.zip_size IS DISTINCT FROM OLD.zip_size OR NEW.source_time IS DISTINCT FROM OLD.source_time OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms OR (OLD.object_verified = 1 AND NEW.object_verified <> 1) OR (OLD.object_verified = 0 AND NEW.object_verified = 1 AND NOT (OLD.status = 'uploading' AND NEW.status = 'uploaded')) OR (OLD.review_hold = 1 AND NEW.review_hold <> 1) OR (OLD.recovery_invalidated = 1 AND NEW.recovery_invalidated <> 1) OR (OLD.status = 'receiving' AND NEW.status NOT IN ('receiving', 'uploading', 'expired', 'rejected')) OR (OLD.status = 'uploading' AND NEW.status NOT IN ('uploading', 'receiving', 'uploaded', 'expired')) OR (OLD.status = 'uploaded' AND NEW.status NOT IN ('uploaded', 'published', 'rejected')) OR (OLD.status IN ('expired', 'rejected', 'published') AND NEW.status <> OLD.status) OR (OLD.status = 'published' AND NEW.published_version_id IS DISTINCT FROM OLD.published_version_id) THEN
        RAISE EXCEPTION 'Go upload identity and verified object are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_go_upload_identity_immutable BEFORE UPDATE ON registry_go_upload_sessions
FOR EACH ROW EXECUTE FUNCTION registry_go_upload_identity_immutable();
-- +goose StatementEnd

CREATE TABLE registry_go_review_decisions (
    decision_id TEXT PRIMARY KEY CHECK (length(decision_id) = 36),
    upload_session_id TEXT NOT NULL REFERENCES registry_go_upload_sessions (upload_session_id) ON DELETE RESTRICT,
    reviewer_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    grant_id TEXT NOT NULL REFERENCES registry_go_reviewer_grants (grant_id) ON DELETE RESTRICT,
    publisher_grant_id TEXT REFERENCES registry_repository_grants (grant_id) ON DELETE RESTRICT,
    policy_revision BIGINT NOT NULL CHECK (policy_revision >= 0),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reason TEXT,
    decided_at TEXT NOT NULL,
    CHECK ((decision = 'approved' AND reason IS NULL AND publisher_grant_id IS NOT NULL) OR (decision = 'rejected' AND reason IS NOT NULL AND length(trim(reason)) BETWEEN 1 AND 1000))
);
CREATE INDEX registry_go_review_decisions_session_idx ON registry_go_review_decisions (upload_session_id, decision_id);

-- +goose StatementBegin
CREATE FUNCTION registry_go_review_decision_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Go review decisions are immutable';
END;
$$;
CREATE TRIGGER registry_go_review_decision_immutable BEFORE UPDATE OR DELETE ON registry_go_review_decisions
FOR EACH ROW EXECUTE FUNCTION registry_go_review_decision_immutable();
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION registry_go_version_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Go module versions are immutable';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER registry_go_version_immutable BEFORE UPDATE ON registry_go_module_versions
FOR EACH ROW EXECUTE FUNCTION registry_go_version_immutable();
CREATE TRIGGER registry_go_version_no_delete BEFORE DELETE ON registry_go_module_versions
FOR EACH ROW EXECUTE FUNCTION registry_go_version_immutable();
-- +goose StatementEnd

-- +goose Down
-- Forward-only: published module identities and content must not be discarded.
