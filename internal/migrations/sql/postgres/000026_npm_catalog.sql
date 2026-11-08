-- +goose Up
-- Catalog only: no npm publication, dist-tags or serving is enabled here.
CREATE TABLE registry_npm_packages (
    package_id TEXT PRIMARY KEY CHECK (length(package_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'npm' CHECK (repository_format = 'npm'),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 214 AND name = lower(name)),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT,
    UNIQUE (repository_id, name),
    UNIQUE (package_id, workspace_id, repository_id)
);

CREATE TABLE registry_npm_versions (
    npm_version_id TEXT PRIMARY KEY CHECK (length(npm_version_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    package_id TEXT NOT NULL,
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 255),
    version_identity TEXT NOT NULL CHECK (length(version_identity) BETWEEN 1 AND 255 AND version_identity = split_part(version, '+', 1)),
    manifest TEXT NOT NULL CHECK (length(manifest) BETWEEN 2 AND 16777216),
    tarball_sha256 TEXT NOT NULL CHECK (tarball_sha256 ~ '^[0-9a-f]{64}$'),
    tarball_size BIGINT NOT NULL CHECK (tarball_size BETWEEN 1 AND 67108864),
    integrity TEXT NOT NULL CHECK (integrity ~ '^sha512-[A-Za-z0-9+/]{86}==$'),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (package_id, workspace_id, repository_id) REFERENCES registry_npm_packages (package_id, workspace_id, repository_id) ON DELETE RESTRICT,
    UNIQUE (package_id, version_identity)
);
CREATE INDEX registry_npm_versions_lookup_idx ON registry_npm_versions (workspace_id, repository_id, package_id);

-- +goose StatementBegin
CREATE FUNCTION registry_npm_identity_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'npm catalog identity and content are immutable';
END;
$$;
CREATE TRIGGER registry_npm_package_immutable BEFORE UPDATE OR DELETE ON registry_npm_packages FOR EACH ROW EXECUTE FUNCTION registry_npm_identity_immutable();
CREATE TRIGGER registry_npm_version_immutable BEFORE UPDATE OR DELETE ON registry_npm_versions FOR EACH ROW EXECUTE FUNCTION registry_npm_identity_immutable();
-- +goose StatementEnd

-- +goose Down
-- Forward-only: package and version identities must not be discarded.
