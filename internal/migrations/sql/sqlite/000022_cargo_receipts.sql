-- +goose Up
-- No table references reservations yet. The transactional rebuild extends the
-- state machine without changing previously applied migration checksums.
ALTER TABLE registry_cargo_reservations RENAME TO registry_cargo_reservations_v21;
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
    status TEXT NOT NULL CHECK (status IN ('reserved', 'uploading', 'uploaded', 'expired', 'cancelled')),
    upload_claim_id TEXT,
    object_verified INTEGER NOT NULL DEFAULT 0 CHECK (object_verified IN (0, 1)),
    index_entry TEXT,
    review_hold INTEGER NOT NULL DEFAULT 0 CHECK (review_hold IN (0, 1)),
    recovery_invalidated INTEGER NOT NULL DEFAULT 0 CHECK (recovery_invalidated IN (0, 1)),
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > created_at_ms),
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT,
    CHECK ((status = 'uploading' AND upload_claim_id IS NOT NULL) OR (status <> 'uploading' AND upload_claim_id IS NULL)),
    CHECK ((status = 'uploaded' AND object_verified = 1 AND index_entry IS NOT NULL AND length(index_entry) BETWEEN 1 AND 16777216) OR (status <> 'uploaded' AND object_verified = 0 AND index_entry IS NULL))
);
INSERT INTO registry_cargo_reservations (reservation_id, workspace_id, repository_id, repository_format, name, name_identity, version, version_identity, archive_sha256, archive_size, metadata_sha256, token_id, created_by, status, recovery_invalidated, created_at_ms, expires_at_ms)
SELECT reservation_id, workspace_id, repository_id, repository_format, name, name_identity, version, version_identity, archive_sha256, archive_size, metadata_sha256, token_id, created_by, status, recovery_invalidated, created_at_ms, expires_at_ms FROM registry_cargo_reservations_v21;
DROP TABLE registry_cargo_reservations_v21;
CREATE UNIQUE INDEX registry_cargo_reservation_active_identity_idx ON registry_cargo_reservations (repository_id, name_identity, version_identity) WHERE status IN ('reserved', 'uploading', 'uploaded');
CREATE INDEX registry_cargo_reservation_expiry_idx ON registry_cargo_reservations (status, expires_at_ms);

-- +goose StatementBegin
CREATE TRIGGER registry_cargo_reservation_immutable BEFORE UPDATE ON registry_cargo_reservations
WHEN NEW.reservation_id <> OLD.reservation_id OR NEW.workspace_id <> OLD.workspace_id OR NEW.repository_id <> OLD.repository_id OR NEW.repository_format <> OLD.repository_format OR NEW.name <> OLD.name OR NEW.name_identity <> OLD.name_identity OR NEW.version <> OLD.version OR NEW.version_identity <> OLD.version_identity OR NEW.archive_sha256 <> OLD.archive_sha256 OR NEW.archive_size <> OLD.archive_size OR NEW.metadata_sha256 <> OLD.metadata_sha256 OR NEW.token_id <> OLD.token_id OR NEW.created_by <> OLD.created_by OR NEW.created_at_ms <> OLD.created_at_ms OR NEW.expires_at_ms <> OLD.expires_at_ms OR (OLD.recovery_invalidated = 1 AND NEW.recovery_invalidated <> 1) OR (OLD.review_hold = 1 AND NEW.review_hold <> 1) OR (OLD.status = 'reserved' AND NEW.status NOT IN ('reserved', 'uploading', 'expired', 'cancelled')) OR (OLD.status = 'uploading' AND NEW.status NOT IN ('uploading', 'reserved', 'uploaded', 'expired')) OR (OLD.status = 'uploaded' AND (NEW.status <> 'uploaded' OR NEW.index_entry IS NOT OLD.index_entry OR NEW.object_verified <> 1)) OR (OLD.status IN ('expired', 'cancelled') AND NEW.status <> OLD.status)
BEGIN
    SELECT RAISE(ABORT, 'Cargo reservation identity and receipt are immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_cargo_reservation_no_delete BEFORE DELETE ON registry_cargo_reservations
BEGIN
    SELECT RAISE(ABORT, 'Cargo reservation history is immutable');
END;
-- +goose StatementEnd

-- +goose Down
-- Forward-only: verified receipts and reservation history must not be discarded.
