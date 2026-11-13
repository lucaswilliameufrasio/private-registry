-- +goose Up
CREATE TABLE registry_oci_write_tokens (
    token_id TEXT PRIMARY KEY CHECK (length(token_id) = 36),
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'oci' CHECK (repository_format = 'oci'),
    publisher_grant_id TEXT NOT NULL REFERENCES registry_repository_grants (grant_id) ON DELETE RESTRICT,
    reader_grant_id TEXT REFERENCES registry_repository_grants (grant_id) ON DELETE RESTRICT,
    secret_sha256 TEXT NOT NULL CHECK (secret_sha256 ~ '^[0-9a-f]{64}$'),
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > created_at_ms),
    revoked_at_ms BIGINT,
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT
);
CREATE INDEX registry_oci_write_tokens_user_idx ON registry_oci_write_tokens (user_id, token_id);

-- +goose StatementBegin
CREATE FUNCTION registry_oci_write_token_reader_grant_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.reader_grant_id IS DISTINCT FROM OLD.reader_grant_id THEN
        RAISE EXCEPTION 'OCI token reader grant is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_oci_write_token_reader_grant_immutable BEFORE UPDATE OF reader_grant_id ON registry_oci_write_tokens FOR EACH ROW EXECUTE FUNCTION registry_oci_write_token_reader_grant_immutable();
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION registry_revoke_oci_write_tokens_on_inactive() RETURNS trigger AS $$
BEGIN
    IF OLD.status = 'active' AND NEW.status <> 'active' THEN
        UPDATE registry_oci_write_tokens SET revoked_at_ms = (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT
        WHERE user_id = NEW.user_id AND revoked_at_ms IS NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER registry_oci_write_tokens_revoke_on_user_inactive
AFTER UPDATE OF status ON registry_users
FOR EACH ROW EXECUTE FUNCTION registry_revoke_oci_write_tokens_on_inactive();



CREATE TABLE registry_oci_blobs (
    repository_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'oci' CHECK (repository_format = 'oci'),
    digest TEXT NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (repository_id, digest),
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT
);

CREATE TABLE registry_oci_manifests (
    repository_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'oci' CHECK (repository_format = 'oci'),
    digest TEXT NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    media_type TEXT NOT NULL CHECK (length(media_type) BETWEEN 1 AND 255),
    content BYTEA NOT NULL CHECK (octet_length(content) BETWEEN 2 AND 4194304),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (repository_id, digest),
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT
);

-- Reference edges recorded at commit time so that a later reachability-based
-- collector or backup inventory never has to re-parse manifests.
CREATE TABLE registry_oci_manifest_references (
    repository_id TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    referenced_digest TEXT NOT NULL CHECK (length(referenced_digest) = 71),
    kind TEXT NOT NULL CHECK (kind IN ('blob', 'manifest')),
    PRIMARY KEY (repository_id, manifest_digest, referenced_digest, kind),
    FOREIGN KEY (repository_id, manifest_digest) REFERENCES registry_oci_manifests (repository_id, digest) ON DELETE RESTRICT
);
CREATE INDEX registry_oci_manifest_references_target_idx ON registry_oci_manifest_references (repository_id, referenced_digest);

CREATE TABLE registry_oci_tags (
    repository_id TEXT NOT NULL,
    image_name TEXT NOT NULL CHECK (length(image_name) BETWEEN 1 AND 180),
    tag TEXT NOT NULL CHECK (length(tag) BETWEEN 1 AND 128),
    manifest_digest TEXT NOT NULL,
    updated_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (repository_id, image_name, tag),
    FOREIGN KEY (repository_id, manifest_digest) REFERENCES registry_oci_manifests (repository_id, digest) ON DELETE RESTRICT
);

-- +goose Down
-- Forward-only: credential revocation records and published images must not be discarded.
