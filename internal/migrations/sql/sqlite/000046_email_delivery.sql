-- +goose Up
-- An invitation may be delivered by email. Redeeming an emailed invitation
-- proves the new account owns that address.
ALTER TABLE registry_workspace_invitations ADD COLUMN email TEXT CHECK (email IS NULL OR length(email) BETWEEN 3 AND 254);

-- A person asks for their own recovery link by email; those requests never
-- cancel a link an administrator issued.
ALTER TABLE registry_password_resets ADD COLUMN self_requested INTEGER NOT NULL DEFAULT 0 CHECK (self_requested IN (0, 1));

-- Single-use links that confirm a person owns the address they set on their
-- account. The address is applied only when the link is used.
CREATE TABLE registry_email_verifications (
    verification_id TEXT PRIMARY KEY CHECK (length(verification_id) = 36),
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    token_sha256 TEXT NOT NULL CHECK (length(token_sha256) = 64),
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > created_at_ms),
    used_at_ms INTEGER,
    revoked_at_ms INTEGER
);
CREATE INDEX registry_email_verifications_user_idx ON registry_email_verifications (user_id, verification_id);

-- +goose Down
-- Forward-only: verification and recovery records are audit evidence.
