-- +goose Up
CREATE TABLE registry_auth_attempt_buckets (
    bucket_key TEXT PRIMARY KEY CHECK (
        length(bucket_key) = 64
        AND bucket_key ~ '^[0-9a-f]{64}$'
    ),
    last_attempt_at BIGINT NOT NULL,
    attempt_times BYTEA NOT NULL CHECK (
        octet_length(attempt_times) BETWEEN 8 AND 160
        AND octet_length(attempt_times) % 8 = 0
    )
);

CREATE INDEX registry_auth_attempt_buckets_window_idx
    ON registry_auth_attempt_buckets (last_attempt_at);

-- +goose Down
-- Forward-only: authentication attempt state must not be dropped automatically.
