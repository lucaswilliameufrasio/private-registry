-- +goose Up
CREATE TABLE registry_jobs (
    job_id TEXT PRIMARY KEY CHECK (length(job_id) = 36),
    idempotency_key TEXT NOT NULL UNIQUE CHECK (length(idempotency_key) BETWEEN 1 AND 200),
    kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 80),
    payload TEXT NOT NULL CHECK (length(payload) <= 16384),
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
    initial_available_at_ms BIGINT NOT NULL,
    available_at_ms BIGINT NOT NULL,
    lease_token TEXT,
    lease_until_ms BIGINT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    CHECK (attempts <= max_attempts),
    CHECK ((status = 'running' AND lease_token IS NOT NULL AND lease_until_ms IS NOT NULL)
        OR (status <> 'running' AND lease_token IS NULL AND lease_until_ms IS NULL))
);
CREATE INDEX registry_jobs_ready_idx ON registry_jobs (status, kind, available_at_ms, job_id);
CREATE INDEX registry_jobs_lease_idx ON registry_jobs (status, lease_until_ms, job_id);

-- +goose Down
-- Forward-only: durable jobs and their idempotency records must not be dropped.
