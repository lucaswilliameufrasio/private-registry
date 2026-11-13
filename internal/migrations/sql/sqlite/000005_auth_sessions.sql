-- +goose Up
CREATE TABLE registry_auth_sessions (
    session_id TEXT PRIMARY KEY CHECK (length(session_id) = 36),
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    bearer_hash TEXT NOT NULL UNIQUE CHECK (
        length(bearer_hash) = 64
        AND bearer_hash NOT GLOB '*[^0-9a-f]*'
    ),
    csrf_hash TEXT NOT NULL CHECK (
        length(csrf_hash) = 64
        AND csrf_hash NOT GLOB '*[^0-9a-f]*'
    ),
    level TEXT NOT NULL CHECK (level IN ('enrollment_only', 'mfa_challenge', 'standard', 'mfa')),
    created_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL,
    idle_expires_at TEXT NOT NULL,
    mfa_verified_at TEXT,
    revoked_at TEXT,
    CHECK (
        (level = 'mfa' AND mfa_verified_at IS NOT NULL)
        OR (level <> 'mfa' AND mfa_verified_at IS NULL)
    )
);

CREATE INDEX registry_auth_sessions_user_idx
    ON registry_auth_sessions (user_id, revoked_at, absolute_expires_at);

-- +goose Down
-- Forward-only: revocable authentication sessions must not be dropped automatically.
