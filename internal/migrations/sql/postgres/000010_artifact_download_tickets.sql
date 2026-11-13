-- +goose Up
CREATE TABLE registry_generic_download_tickets (
    token_sha256 TEXT PRIMARY KEY CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
    artifact_file_id TEXT NOT NULL REFERENCES registry_generic_artifact_files (artifact_file_id) ON DELETE RESTRICT,
    issued_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by TEXT REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    CHECK ((revoked_at IS NULL AND revoked_by IS NULL) OR (revoked_at IS NOT NULL AND revoked_by IS NOT NULL))
);

CREATE INDEX registry_generic_download_tickets_file_idx
    ON registry_generic_download_tickets (artifact_file_id, expires_at);

CREATE INDEX registry_generic_download_tickets_expiry_idx
    ON registry_generic_download_tickets (expires_at);

-- +goose Down
-- Forward-only: live download capabilities must not be invalidated by automatic downgrade.
