-- +goose Up
ALTER TABLE registry_cargo_reservations DROP CONSTRAINT registry_cargo_reservations_status_check;
ALTER TABLE registry_cargo_reservations ADD CONSTRAINT registry_cargo_reservations_status_check CHECK (status IN ('reserved', 'uploading', 'uploaded', 'expired', 'cancelled'));
ALTER TABLE registry_cargo_reservations ADD COLUMN upload_claim_id TEXT;
ALTER TABLE registry_cargo_reservations ADD COLUMN object_verified INTEGER NOT NULL DEFAULT 0 CHECK (object_verified IN (0, 1));
ALTER TABLE registry_cargo_reservations ADD COLUMN index_entry TEXT;
ALTER TABLE registry_cargo_reservations ADD COLUMN review_hold INTEGER NOT NULL DEFAULT 0 CHECK (review_hold IN (0, 1));
ALTER TABLE registry_cargo_reservations ADD CONSTRAINT registry_cargo_reservation_claim_check CHECK ((status = 'uploading' AND upload_claim_id IS NOT NULL) OR (status <> 'uploading' AND upload_claim_id IS NULL));
ALTER TABLE registry_cargo_reservations ADD CONSTRAINT registry_cargo_reservation_receipt_check CHECK ((status = 'uploaded' AND object_verified = 1 AND index_entry IS NOT NULL AND length(index_entry) BETWEEN 1 AND 16777216) OR (status <> 'uploaded' AND object_verified = 0 AND index_entry IS NULL));
DROP INDEX registry_cargo_reservation_active_identity_idx;
CREATE UNIQUE INDEX registry_cargo_reservation_active_identity_idx ON registry_cargo_reservations (repository_id, name_identity, version_identity) WHERE status IN ('reserved', 'uploading', 'uploaded');
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION registry_cargo_reservation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Cargo reservation history is immutable';
    END IF;
    IF NEW.reservation_id IS DISTINCT FROM OLD.reservation_id OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.repository_id IS DISTINCT FROM OLD.repository_id OR NEW.repository_format IS DISTINCT FROM OLD.repository_format OR NEW.name IS DISTINCT FROM OLD.name OR NEW.name_identity IS DISTINCT FROM OLD.name_identity OR NEW.version IS DISTINCT FROM OLD.version OR NEW.version_identity IS DISTINCT FROM OLD.version_identity OR NEW.archive_sha256 IS DISTINCT FROM OLD.archive_sha256 OR NEW.archive_size IS DISTINCT FROM OLD.archive_size OR NEW.metadata_sha256 IS DISTINCT FROM OLD.metadata_sha256 OR NEW.token_id IS DISTINCT FROM OLD.token_id OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at_ms IS DISTINCT FROM OLD.created_at_ms OR NEW.expires_at_ms IS DISTINCT FROM OLD.expires_at_ms OR (OLD.recovery_invalidated = 1 AND NEW.recovery_invalidated <> 1) OR (OLD.review_hold = 1 AND NEW.review_hold <> 1) OR (OLD.status = 'reserved' AND NEW.status NOT IN ('reserved', 'uploading', 'expired', 'cancelled')) OR (OLD.status = 'uploading' AND NEW.status NOT IN ('uploading', 'reserved', 'uploaded', 'expired')) OR (OLD.status = 'uploaded' AND (NEW.status <> 'uploaded' OR NEW.index_entry IS DISTINCT FROM OLD.index_entry OR NEW.object_verified <> 1)) OR (OLD.status IN ('expired', 'cancelled') AND NEW.status <> OLD.status) THEN
        RAISE EXCEPTION 'Cargo reservation identity and receipt are immutable';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- Forward-only: verified receipts and reservation history must not be discarded.
