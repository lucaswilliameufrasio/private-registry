-- +goose Up
CREATE TABLE registry_personal_read_tokens (
    token_id TEXT PRIMARY KEY CHECK (length(token_id) = 36),
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    reader_grant_id TEXT NOT NULL REFERENCES registry_repository_grants (grant_id) ON DELETE RESTRICT,
    secret_sha256 TEXT NOT NULL CHECK (secret_sha256 ~ '^[0-9a-f]{64}$'),
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > created_at_ms),
    revoked_at_ms BIGINT,
    FOREIGN KEY (repository_id, workspace_id) REFERENCES registry_repositories (repository_id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX registry_personal_read_tokens_user_idx ON registry_personal_read_tokens (user_id, token_id);
CREATE INDEX registry_personal_read_tokens_expiry_idx ON registry_personal_read_tokens (expires_at_ms);

-- +goose StatementBegin
CREATE FUNCTION registry_revoke_personal_read_tokens_on_inactive() RETURNS trigger AS $$
BEGIN
    IF OLD.status = 'active' AND NEW.status <> 'active' THEN
        UPDATE registry_personal_read_tokens SET revoked_at_ms = (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT
        WHERE user_id = NEW.user_id AND revoked_at_ms IS NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER registry_personal_read_tokens_revoke_on_user_inactive
AFTER UPDATE OF status ON registry_users
FOR EACH ROW EXECUTE FUNCTION registry_revoke_personal_read_tokens_on_inactive();

-- +goose Down
-- Forward-only: credential revocation records must not be discarded silently.
