-- +goose Up
CREATE UNIQUE INDEX registry_npm_version_scope_idx ON registry_npm_versions (npm_version_id, workspace_id, repository_id);
CREATE TABLE registry_npm_publications (
    reservation_id TEXT PRIMARY KEY,
    npm_version_id TEXT NOT NULL UNIQUE,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    FOREIGN KEY (reservation_id, workspace_id, repository_id) REFERENCES registry_npm_reservations (reservation_id, workspace_id, repository_id) ON DELETE RESTRICT,
    FOREIGN KEY (npm_version_id, workspace_id, repository_id) REFERENCES registry_npm_versions (npm_version_id, workspace_id, repository_id) ON DELETE RESTRICT
);
-- +goose StatementBegin
CREATE FUNCTION registry_npm_publication_match() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM registry_npm_reservations r
        JOIN registry_npm_versions v ON v.npm_version_id = NEW.npm_version_id AND v.workspace_id = NEW.workspace_id AND v.repository_id = NEW.repository_id
        JOIN registry_npm_packages p ON p.package_id = v.package_id AND p.workspace_id = v.workspace_id AND p.repository_id = v.repository_id
        WHERE r.reservation_id = NEW.reservation_id AND r.workspace_id = NEW.workspace_id AND r.repository_id = NEW.repository_id
          AND r.status = 'uploaded' AND r.object_verified = 1 AND r.recovery_invalidated = 0
          AND r.name = p.name AND r.version = v.version AND r.version_identity = v.version_identity
          AND r.tarball_sha256 = v.tarball_sha256 AND r.tarball_size = v.tarball_size
          AND r.manifest = v.manifest AND r.integrity = v.integrity AND r.created_by = v.created_by
    ) THEN
        RAISE EXCEPTION 'npm publication must match its verified receipt';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_npm_publication_match BEFORE INSERT ON registry_npm_publications FOR EACH ROW EXECUTE FUNCTION registry_npm_publication_match();
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION registry_npm_publication_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'npm publication history is immutable';
END;
$$;
CREATE TRIGGER registry_npm_publication_immutable BEFORE UPDATE OR DELETE ON registry_npm_publications FOR EACH ROW EXECUTE FUNCTION registry_npm_publication_immutable();
-- +goose StatementEnd
-- +goose Down
-- Forward-only: publication history must not be discarded.
