-- +goose Up
CREATE TABLE registry_auth_attempt_buckets (
    bucket_key TEXT PRIMARY KEY CHECK (
        length(bucket_key) = 64
        AND bucket_key NOT GLOB '*[^0-9a-f]*'
    ),
    last_attempt_at INTEGER NOT NULL,
    attempt_times BLOB NOT NULL CHECK (
        typeof(attempt_times) = 'blob'
        AND length(attempt_times) BETWEEN 8 AND 160
        AND length(attempt_times) % 8 = 0
    )
);

CREATE INDEX registry_auth_attempt_buckets_window_idx
    ON registry_auth_attempt_buckets (last_attempt_at);

-- +goose Down
-- Forward-only: authentication attempt state must not be dropped automatically.
