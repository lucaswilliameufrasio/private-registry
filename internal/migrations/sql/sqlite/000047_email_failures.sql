-- +goose Up
-- Why an email was given up on, for the administrators who review and resend
-- it. Recipients and links stay sealed in the job payload; only the template,
-- provider and a short error code are kept here.
CREATE TABLE registry_email_failures (
    job_id TEXT PRIMARY KEY REFERENCES registry_jobs (job_id) ON DELETE RESTRICT,
    template TEXT NOT NULL CHECK (length(template) BETWEEN 1 AND 80),
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 40),
    error TEXT NOT NULL CHECK (length(error) BETWEEN 1 AND 200),
    failed_at_ms INTEGER NOT NULL,
    resent_job_id TEXT REFERENCES registry_jobs (job_id) ON DELETE RESTRICT,
    resent_by TEXT REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    resent_at_ms INTEGER,
    CHECK ((resent_job_id IS NULL) = (resent_by IS NULL) AND (resent_job_id IS NULL) = (resent_at_ms IS NULL))
);
CREATE INDEX registry_email_failures_open_idx ON registry_email_failures (resent_job_id, failed_at_ms);

-- +goose Down
-- Forward-only: delivery failures are audit evidence.
