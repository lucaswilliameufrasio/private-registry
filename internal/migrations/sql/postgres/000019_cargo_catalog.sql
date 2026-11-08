-- +goose Up
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
    archive_sha256 TEXT NOT NULL CHECK (archive_sha256 ~ '^[0-9a-f]{64}$'),
    archive_size BIGINT NOT NULL CHECK (archive_size BETWEEN 1 AND 1073741824),
    yanked INTEGER NOT NULL DEFAULT 0 CHECK (yanked IN (0, 1)),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (package_id, workspace_id, repository_id) REFERENCES registry_cargo_packages (package_id, workspace_id, repository_id) ON DELETE RESTRICT,
    UNIQUE (package_id, version_identity)
);
CREATE INDEX registry_cargo_versions_lookup_idx ON registry_cargo_versions (workspace_id, repository_id, package_id);

-- +goose StatementBegin
CREATE FUNCTION registry_cargo_package_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Cargo package identity is immutable';
END;
$$;
CREATE TRIGGER registry_cargo_package_immutable BEFORE UPDATE OR DELETE ON registry_cargo_packages
FOR EACH ROW EXECUTE FUNCTION registry_cargo_package_immutable();
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION registry_cargo_version_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Cargo version identity and content are immutable';
    END IF;
    IF NEW.cargo_version_id IS DISTINCT FROM OLD.cargo_version_id OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.repository_id IS DISTINCT FROM OLD.repository_id OR NEW.package_id IS DISTINCT FROM OLD.package_id OR NEW.version IS DISTINCT FROM OLD.version OR NEW.version_identity IS DISTINCT FROM OLD.version_identity OR NEW.index_entry IS DISTINCT FROM OLD.index_entry OR NEW.archive_sha256 IS DISTINCT FROM OLD.archive_sha256 OR NEW.archive_size IS DISTINCT FROM OLD.archive_size OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'Cargo version identity and content are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_cargo_version_immutable BEFORE UPDATE OR DELETE ON registry_cargo_versions
FOR EACH ROW EXECUTE FUNCTION registry_cargo_version_immutable();
-- +goose StatementEnd

-- +goose Down
-- Forward-only: package and version identities must not be discarded.
