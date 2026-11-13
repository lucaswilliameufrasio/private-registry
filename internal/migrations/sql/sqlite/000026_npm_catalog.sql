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
    version_identity TEXT NOT NULL CHECK (length(version_identity) BETWEEN 1 AND 255 AND version_identity = CASE WHEN instr(version, '+') = 0 THEN version ELSE substr(version, 1, instr(version, '+') - 1) END),
    manifest TEXT NOT NULL CHECK (length(manifest) BETWEEN 2 AND 16777216),
    tarball_sha256 TEXT NOT NULL CHECK (length(tarball_sha256) = 64 AND tarball_sha256 = lower(tarball_sha256) AND tarball_sha256 NOT GLOB '*[^0-9a-f]*'),
    tarball_size INTEGER NOT NULL CHECK (tarball_size BETWEEN 1 AND 67108864),
    integrity TEXT NOT NULL CHECK (length(integrity) = 95 AND substr(integrity, 1, 7) = 'sha512-' AND substr(integrity, -2) = '==' AND substr(integrity, 8, 86) NOT GLOB '*[^A-Za-z0-9+/]*'),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (package_id, workspace_id, repository_id) REFERENCES registry_npm_packages (package_id, workspace_id, repository_id) ON DELETE RESTRICT,
    UNIQUE (package_id, version_identity)
);
CREATE INDEX registry_npm_versions_lookup_idx ON registry_npm_versions (workspace_id, repository_id, package_id);

-- +goose StatementBegin
CREATE TRIGGER registry_npm_package_no_update BEFORE UPDATE ON registry_npm_packages
BEGIN
    SELECT RAISE(ABORT, 'npm package identity is immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_npm_package_no_delete BEFORE DELETE ON registry_npm_packages
BEGIN
    SELECT RAISE(ABORT, 'npm package identity is immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_npm_version_no_update BEFORE UPDATE ON registry_npm_versions
BEGIN
    SELECT RAISE(ABORT, 'npm version identity and content are immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_npm_version_no_delete BEFORE DELETE ON registry_npm_versions
BEGIN
    SELECT RAISE(ABORT, 'npm version identity and content are immutable');
END;
-- +goose StatementEnd

-- +goose Down
-- Forward-only: package and version identities must not be discarded.
