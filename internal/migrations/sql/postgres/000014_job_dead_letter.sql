-- +goose Up
ALTER TABLE registry_jobs ADD COLUMN revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0);
ALTER TABLE registry_jobs ADD COLUMN last_failure_code TEXT CHECK (last_failure_code IS NULL OR last_failure_code IN ('operation_failed', 'lease_expired'));

-- +goose Down
-- Forward-only: job revisions and dead-letter diagnostics must not be discarded.
