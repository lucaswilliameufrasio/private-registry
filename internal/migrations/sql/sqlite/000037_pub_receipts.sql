-- +goose Up
-- No table references reservations yet; this rebuild preserves existing rows.
ALTER TABLE registry_pub_reservations RENAME TO registry_pub_reservations_v36;
CREATE TABLE registry_pub_reservations (
    reservation_id TEXT PRIMARY KEY CHECK (length(reservation_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'pub' CHECK (repository_format = 'pub'),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64 AND name = lower(name)),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 255),
    version_identity TEXT NOT NULL CHECK (length(version_identity) BETWEEN 1 AND 255 AND version_identity = CASE WHEN instr(version, '+') = 0 THEN version ELSE substr(version, 1, instr(version, '+') - 1) END),
    tarball_sha256 TEXT NOT NULL CHECK (length(tarball_sha256) = 64 AND tarball_sha256 = lower(tarball_sha256) AND tarball_sha256 NOT GLOB '*[^0-9a-f]*'),
    tarball_size INTEGER NOT NULL CHECK (tarball_size BETWEEN 1 AND 67108864),
    metadata_sha256 TEXT NOT NULL CHECK (length(metadata_sha256) = 64 AND metadata_sha256 = lower(metadata_sha256) AND metadata_sha256 NOT GLOB '*[^0-9a-f]*'),
    token_id TEXT NOT NULL REFERENCES registry_pub_write_tokens (token_id) ON DELETE RESTRICT,
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('reserved', 'uploading', 'uploaded', 'expired', 'cancelled')),
    upload_claim_id TEXT,
    object_verified INTEGER NOT NULL DEFAULT 0 CHECK (object_verified IN (0, 1)),
    manifest TEXT,
    review_hold INTEGER NOT NULL DEFAULT 0 CHECK (review_hold IN (0, 1)),
    recovery_invalidated INTEGER NOT NULL DEFAULT 0 CHECK (recovery_invalidated IN (0, 1)),
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > created_at_ms),
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT,
    CHECK ((status = 'uploading' AND upload_claim_id IS NOT NULL) OR (status <> 'uploading' AND upload_claim_id IS NULL)),
    CHECK ((status = 'uploaded' AND object_verified = 1 AND manifest IS NOT NULL AND length(manifest) BETWEEN 1 AND 1048576) OR (status <> 'uploaded' AND object_verified = 0 AND manifest IS NULL))
);
INSERT INTO registry_pub_reservations (reservation_id, workspace_id, repository_id, repository_format, name, version, version_identity, tarball_sha256, tarball_size, metadata_sha256, token_id, created_by, status, recovery_invalidated, created_at_ms, expires_at_ms)
SELECT reservation_id, workspace_id, repository_id, repository_format, name, version, version_identity, tarball_sha256, tarball_size, metadata_sha256, token_id, created_by, status, recovery_invalidated, created_at_ms, expires_at_ms FROM registry_pub_reservations_v36;
DROP TABLE registry_pub_reservations_v36;
CREATE UNIQUE INDEX registry_pub_reservation_active_identity_idx ON registry_pub_reservations (repository_id, name, version_identity) WHERE status IN ('reserved', 'uploading', 'uploaded');
CREATE INDEX registry_pub_reservation_expiry_idx ON registry_pub_reservations (status, expires_at_ms);

-- +goose StatementBegin
CREATE TRIGGER registry_pub_reservation_immutable BEFORE UPDATE ON registry_pub_reservations
WHEN NEW.reservation_id <> OLD.reservation_id OR NEW.workspace_id <> OLD.workspace_id OR NEW.repository_id <> OLD.repository_id OR NEW.repository_format <> OLD.repository_format OR NEW.name <> OLD.name OR NEW.version <> OLD.version OR NEW.version_identity <> OLD.version_identity OR NEW.tarball_sha256 <> OLD.tarball_sha256 OR NEW.tarball_size <> OLD.tarball_size OR NEW.metadata_sha256 <> OLD.metadata_sha256 OR NEW.token_id <> OLD.token_id OR NEW.created_by <> OLD.created_by OR NEW.created_at_ms <> OLD.created_at_ms OR NEW.expires_at_ms <> OLD.expires_at_ms OR (OLD.recovery_invalidated = 1 AND NEW.recovery_invalidated <> 1) OR (OLD.review_hold = 1 AND NEW.review_hold <> 1) OR (OLD.status = 'reserved' AND NEW.status NOT IN ('reserved', 'uploading', 'expired', 'cancelled')) OR (OLD.status = 'uploading' AND NEW.status NOT IN ('uploading', 'reserved', 'uploaded', 'expired')) OR (OLD.status = 'uploaded' AND (NEW.status <> 'uploaded' OR NEW.manifest IS NOT OLD.manifest OR NEW.object_verified <> 1)) OR (OLD.status IN ('expired', 'cancelled') AND NEW.status <> OLD.status)
BEGIN
    SELECT RAISE(ABORT, 'pub reservation identity and receipt are immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_pub_reservation_no_delete BEFORE DELETE ON registry_pub_reservations
BEGIN
    SELECT RAISE(ABORT, 'pub reservation history is immutable');
END;
-- +goose StatementEnd

-- +goose Down
-- Forward-only: verified receipts and reservation history must not be discarded.
