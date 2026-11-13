-- +goose Up
-- Catalog-only foundation. The application must not enable Cargo until
-- authorization, reviewed publication, quota and recovery are implemented.
CREATE TABLE registry_cargo_packages (
    package_id TEXT PRIMARY KEY CHECK (length(package_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'cargo' CHECK (repository_format = 'cargo'),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    name_identity TEXT NOT NULL CHECK (length(name_identity) BETWEEN 1 AND 255),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT,
    UNIQUE (repository_id, name_identity),
    UNIQUE (package_id, workspace_id, repository_id)
);

CREATE TABLE registry_cargo_versions (
    cargo_version_id TEXT PRIMARY KEY CHECK (length(cargo_version_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    package_id TEXT NOT NULL,
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 255),
    version_identity TEXT NOT NULL CHECK (length(version_identity) BETWEEN 1 AND 255),
    index_entry TEXT NOT NULL CHECK (length(index_entry) BETWEEN 1 AND 16777216),
    archive_sha256 TEXT NOT NULL CHECK (length(archive_sha256) = 64 AND archive_sha256 = lower(archive_sha256) AND archive_sha256 NOT GLOB '*[^0-9a-f]*'),
    archive_size INTEGER NOT NULL CHECK (archive_size BETWEEN 1 AND 1073741824),
    yanked INTEGER NOT NULL DEFAULT 0 CHECK (yanked IN (0, 1)),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (package_id, workspace_id, repository_id) REFERENCES registry_cargo_packages (package_id, workspace_id, repository_id) ON DELETE RESTRICT,
    UNIQUE (package_id, version_identity)
);
CREATE INDEX registry_cargo_versions_lookup_idx ON registry_cargo_versions (workspace_id, repository_id, package_id);

-- +goose StatementBegin
CREATE TRIGGER registry_cargo_package_immutable BEFORE UPDATE ON registry_cargo_packages
BEGIN
    SELECT RAISE(ABORT, 'Cargo package identity is immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_cargo_package_no_delete BEFORE DELETE ON registry_cargo_packages
BEGIN
    SELECT RAISE(ABORT, 'Cargo package identity is immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_cargo_version_immutable BEFORE UPDATE ON registry_cargo_versions
WHEN NEW.cargo_version_id <> OLD.cargo_version_id OR NEW.workspace_id <> OLD.workspace_id OR NEW.repository_id <> OLD.repository_id OR NEW.package_id <> OLD.package_id OR NEW.version <> OLD.version OR NEW.version_identity <> OLD.version_identity OR NEW.index_entry <> OLD.index_entry OR NEW.archive_sha256 <> OLD.archive_sha256 OR NEW.archive_size <> OLD.archive_size OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'Cargo version identity and content are immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_cargo_version_no_delete BEFORE DELETE ON registry_cargo_versions
BEGIN
    SELECT RAISE(ABORT, 'Cargo version identity and content are immutable');
END;
-- +goose StatementEnd

-- +goose Down
-- Forward-only: package and version identities must not be discarded.
