-- +goose Up
-- A reservation is not a publication or a verified object reference.
CREATE TABLE registry_cargo_reservations (
    reservation_id TEXT PRIMARY KEY CHECK (length(reservation_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'cargo' CHECK (repository_format = 'cargo'),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    name_identity TEXT NOT NULL CHECK (length(name_identity) BETWEEN 1 AND 255),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 255),
    version_identity TEXT NOT NULL CHECK (length(version_identity) BETWEEN 1 AND 255),
    archive_sha256 TEXT NOT NULL CHECK (length(archive_sha256) = 64 AND archive_sha256 = lower(archive_sha256) AND archive_sha256 NOT GLOB '*[^0-9a-f]*'),
    archive_size INTEGER NOT NULL CHECK (archive_size BETWEEN 1 AND 524288000),
    metadata_sha256 TEXT NOT NULL CHECK (length(metadata_sha256) = 64 AND metadata_sha256 = lower(metadata_sha256) AND metadata_sha256 NOT GLOB '*[^0-9a-f]*'),
    token_id TEXT NOT NULL REFERENCES registry_cargo_write_tokens (token_id) ON DELETE RESTRICT,
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('reserved', 'expired', 'cancelled')),
    recovery_invalidated INTEGER NOT NULL DEFAULT 0 CHECK (recovery_invalidated IN (0, 1)),
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > created_at_ms),
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX registry_cargo_reservation_active_identity_idx ON registry_cargo_reservations (repository_id, name_identity, version_identity) WHERE status = 'reserved';
CREATE INDEX registry_cargo_reservation_expiry_idx ON registry_cargo_reservations (status, expires_at_ms);

-- +goose StatementBegin
CREATE TRIGGER registry_cargo_reservation_immutable BEFORE UPDATE ON registry_cargo_reservations
WHEN NEW.reservation_id <> OLD.reservation_id OR NEW.workspace_id <> OLD.workspace_id OR NEW.repository_id <> OLD.repository_id OR NEW.repository_format <> OLD.repository_format OR NEW.name <> OLD.name OR NEW.name_identity <> OLD.name_identity OR NEW.version <> OLD.version OR NEW.version_identity <> OLD.version_identity OR NEW.archive_sha256 <> OLD.archive_sha256 OR NEW.archive_size <> OLD.archive_size OR NEW.metadata_sha256 <> OLD.metadata_sha256 OR NEW.token_id <> OLD.token_id OR NEW.created_by <> OLD.created_by OR NEW.created_at_ms <> OLD.created_at_ms OR NEW.expires_at_ms <> OLD.expires_at_ms OR (OLD.recovery_invalidated = 1 AND NEW.recovery_invalidated <> 1) OR (OLD.status <> 'reserved' AND NEW.status <> OLD.status)
BEGIN
    SELECT RAISE(ABORT, 'Cargo reservation identity and terminal state are immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_cargo_reservation_no_delete BEFORE DELETE ON registry_cargo_reservations
BEGIN
    SELECT RAISE(ABORT, 'Cargo reservation history is immutable');
END;
-- +goose StatementEnd

-- +goose Down
-- Forward-only: reservation and reconciliation history must not be discarded.
