-- +goose Up
CREATE TABLE registry_pub_native_uploads (
    upload_id TEXT PRIMARY KEY CHECK (length(upload_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'pub' CHECK (repository_format = 'pub'),
    token_id TEXT NOT NULL REFERENCES registry_pub_write_tokens (token_id) ON DELETE RESTRICT,
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    reservation_id TEXT,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > created_at_ms),
    recovery_invalidated INTEGER NOT NULL DEFAULT 0 CHECK (recovery_invalidated IN (0, 1)),
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT,
    FOREIGN KEY (reservation_id, workspace_id, repository_id) REFERENCES registry_pub_reservations (reservation_id, workspace_id, repository_id) ON DELETE RESTRICT
);
CREATE INDEX registry_pub_native_uploads_token_idx ON registry_pub_native_uploads (token_id, expires_at_ms);
-- +goose StatementBegin
CREATE TRIGGER registry_pub_native_upload_immutable BEFORE UPDATE ON registry_pub_native_uploads
WHEN NEW.upload_id <> OLD.upload_id OR NEW.workspace_id <> OLD.workspace_id OR NEW.repository_id <> OLD.repository_id OR NEW.repository_format <> OLD.repository_format OR NEW.token_id <> OLD.token_id OR NEW.created_by <> OLD.created_by OR NEW.created_at_ms <> OLD.created_at_ms OR NEW.expires_at_ms <> OLD.expires_at_ms OR (OLD.reservation_id IS NOT NULL AND NEW.reservation_id IS NOT OLD.reservation_id) OR (OLD.recovery_invalidated = 1 AND NEW.recovery_invalidated <> 1)
BEGIN
    SELECT RAISE(ABORT, 'Pub native upload identity is immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_pub_native_upload_no_delete BEFORE DELETE ON registry_pub_native_uploads
BEGIN
    SELECT RAISE(ABORT, 'Pub native upload history is immutable');
END;
-- +goose StatementEnd
-- +goose Down
-- Forward-only: native upload and recovery history must not be discarded.
