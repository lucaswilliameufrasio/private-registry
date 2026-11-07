-- +goose Up
CREATE TABLE registry_personal_read_tokens (
    token_id TEXT PRIMARY KEY CHECK (length(token_id) = 36),
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    reader_grant_id TEXT NOT NULL REFERENCES registry_repository_grants (grant_id) ON DELETE RESTRICT,
    secret_sha256 TEXT NOT NULL CHECK (length(secret_sha256) = 64 AND secret_sha256 = lower(secret_sha256) AND secret_sha256 NOT GLOB '*[^0-9a-f]*'),
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > created_at_ms),
    revoked_at_ms INTEGER,
    FOREIGN KEY (repository_id, workspace_id) REFERENCES registry_repositories (repository_id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX registry_personal_read_tokens_user_idx ON registry_personal_read_tokens (user_id, token_id);
CREATE INDEX registry_personal_read_tokens_expiry_idx ON registry_personal_read_tokens (expires_at_ms);

-- +goose StatementBegin
CREATE TRIGGER registry_personal_read_tokens_revoke_on_user_inactive
AFTER UPDATE OF status ON registry_users
WHEN OLD.status = 'active' AND NEW.status <> 'active'
BEGIN
    UPDATE registry_personal_read_tokens SET revoked_at_ms = CAST(strftime('%s', 'now') AS INTEGER) * 1000
    WHERE user_id = NEW.user_id AND revoked_at_ms IS NULL;
END;
-- +goose StatementEnd

-- +goose Down
-- Forward-only: credential revocation records must not be discarded silently.
