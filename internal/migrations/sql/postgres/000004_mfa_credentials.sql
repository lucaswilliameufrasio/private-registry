-- +goose Up
CREATE TABLE registry_totp_credentials (
    user_id TEXT PRIMARY KEY REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    secret_envelope BYTEA NOT NULL CHECK (octet_length(secret_envelope) = 61),
    status TEXT NOT NULL CHECK (status IN ('pending', 'active')),
    enrollment_expires_at TEXT NOT NULL,
    confirmed_at TEXT,
    last_accepted_step BIGINT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (status = 'pending' AND confirmed_at IS NULL AND last_accepted_step IS NULL)
        OR (status = 'active' AND confirmed_at IS NOT NULL AND last_accepted_step IS NOT NULL)
    )
);

CREATE TABLE registry_mfa_recovery_codes (
    code_id TEXT PRIMARY KEY CHECK (length(code_id) = 36),
    user_id TEXT NOT NULL REFERENCES registry_totp_credentials (user_id) ON DELETE RESTRICT,
    code_hash TEXT NOT NULL CHECK (
        length(code_hash) = 64
        AND code_hash ~ '^[0-9a-f]{64}$'
    ),
    issued_at TEXT NOT NULL,
    consumed_at TEXT,
    UNIQUE (user_id, code_hash)
);

CREATE INDEX registry_mfa_recovery_codes_user_idx
    ON registry_mfa_recovery_codes (user_id, consumed_at);

-- +goose Down
-- Forward-only: MFA credentials and recovery codes must not be dropped automatically.
