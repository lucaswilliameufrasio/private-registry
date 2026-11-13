-- +goose Up
CREATE TABLE registry_cargo_reservations (
    reservation_id TEXT PRIMARY KEY CHECK (length(reservation_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'cargo' CHECK (repository_format = 'cargo'),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    name_identity TEXT NOT NULL CHECK (length(name_identity) BETWEEN 1 AND 255),
    version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 255),
    version_identity TEXT NOT NULL CHECK (length(version_identity) BETWEEN 1 AND 255),
    archive_sha256 TEXT NOT NULL CHECK (archive_sha256 ~ '^[0-9a-f]{64}$'),
    archive_size BIGINT NOT NULL CHECK (archive_size BETWEEN 1 AND 524288000),
    metadata_sha256 TEXT NOT NULL CHECK (metadata_sha256 ~ '^[0-9a-f]{64}$'),
    token_id TEXT NOT NULL REFERENCES registry_cargo_write_tokens (token_id) ON DELETE RESTRICT,
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('reserved', 'expired', 'cancelled')),
    recovery_invalidated INTEGER NOT NULL DEFAULT 0 CHECK (recovery_invalidated IN (0, 1)),
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > created_at_ms),
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX registry_cargo_reservation_active_identity_idx ON registry_cargo_reservations (repository_id, name_identity, version_identity) WHERE status = 'reserved';
CREATE INDEX registry_cargo_reservation_expiry_idx ON registry_cargo_reservations (status, expires_at_ms);

-- +goose StatementBegin
CREATE FUNCTION registry_cargo_reservation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Cargo reservation history is immutable';
    END IF;
    IF NEW.reservation_id IS DISTINCT FROM OLD.reservation_id OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.repository_id IS DISTINCT FROM OLD.repository_id OR NEW.repository_format IS DISTINCT FROM OLD.repository_format OR NEW.name IS DISTINCT FROM OLD.name OR NEW.name_identity IS DISTINCT FROM OLD.name_identity OR NEW.version IS DISTINCT FROM OLD.version OR NEW.version_identity IS DISTINCT FROM OLD.version_identity OR NEW.archive_sha256 IS DISTINCT FROM OLD.archive_sha256 OR NEW.archive_size IS DISTINCT FROM OLD.archive_size OR NEW.metadata_sha256 IS DISTINCT FROM OLD.metadata_sha256 OR NEW.token_id IS DISTINCT FROM OLD.token_id OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms OR (OLD.recovery_invalidated = 1 AND NEW.recovery_invalidated <> 1) OR (OLD.status <> 'reserved' AND NEW.status <> OLD.status) THEN
        RAISE EXCEPTION 'Cargo reservation identity and terminal state are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_cargo_reservation_immutable BEFORE UPDATE OR DELETE ON registry_cargo_reservations
FOR EACH ROW EXECUTE FUNCTION registry_cargo_reservation_immutable();
-- +goose StatementEnd

-- +goose Down
-- Forward-only: reservation and reconciliation history must not be discarded.
