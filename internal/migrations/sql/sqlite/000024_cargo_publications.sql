-- +goose Up
CREATE UNIQUE INDEX registry_cargo_version_scope_idx ON registry_cargo_versions (cargo_version_id, workspace_id, repository_id);
CREATE TABLE registry_cargo_publications (
    reservation_id TEXT PRIMARY KEY,
    cargo_version_id TEXT NOT NULL UNIQUE,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    FOREIGN KEY (reservation_id, workspace_id, repository_id) REFERENCES registry_cargo_reservations (reservation_id, workspace_id, repository_id) ON DELETE RESTRICT,
    FOREIGN KEY (cargo_version_id, workspace_id, repository_id) REFERENCES registry_cargo_versions (cargo_version_id, workspace_id, repository_id) ON DELETE RESTRICT
);
-- +goose StatementBegin
CREATE TRIGGER registry_cargo_publication_match BEFORE INSERT ON registry_cargo_publications
WHEN NOT EXISTS (
    SELECT 1 FROM registry_cargo_reservations r
    JOIN registry_cargo_versions v ON v.cargo_version_id = NEW.cargo_version_id AND v.workspace_id = NEW.workspace_id AND v.repository_id = NEW.repository_id
    JOIN registry_cargo_packages p ON p.package_id = v.package_id AND p.workspace_id = v.workspace_id AND p.repository_id = v.repository_id
    WHERE r.reservation_id = NEW.reservation_id AND r.workspace_id = NEW.workspace_id AND r.repository_id = NEW.repository_id
      AND r.status = 'uploaded' AND r.object_verified = 1 AND r.recovery_invalidated = 0
      AND r.name = p.name AND r.name_identity = p.name_identity
      AND r.version = v.version AND r.version_identity = v.version_identity
      AND r.archive_sha256 = v.archive_sha256 AND r.archive_size = v.archive_size
      AND r.index_entry = v.index_entry AND r.created_by = v.created_by
)
BEGIN
    SELECT RAISE(ABORT, 'Cargo publication must match its verified receipt');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_cargo_publication_no_update BEFORE UPDATE ON registry_cargo_publications
BEGIN
    SELECT RAISE(ABORT, 'Cargo publication history is immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_cargo_publication_no_delete BEFORE DELETE ON registry_cargo_publications
BEGIN
    SELECT RAISE(ABORT, 'Cargo publication history is immutable');
END;
-- +goose StatementEnd
-- +goose Down
-- Forward-only: publication history must not be discarded.
