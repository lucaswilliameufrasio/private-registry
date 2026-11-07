-- +goose Up
ALTER TABLE registry_jobs ADD COLUMN recovery_previous_status TEXT
    CHECK (recovery_previous_status IS NULL OR recovery_previous_status IN ('pending', 'running'));
ALTER TABLE registry_generic_upload_sessions ADD COLUMN recovery_invalidated INTEGER NOT NULL DEFAULT 0
    CHECK (recovery_invalidated IN (0, 1));

-- +goose Down
-- Forward-only: recovery holds must not be silently discarded.
