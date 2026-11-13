-- +goose Up
CREATE TABLE registry_local_credentials (
    user_id TEXT PRIMARY KEY REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    login_name TEXT NOT NULL UNIQUE
        CHECK (
            login_name = lower(login_name)
            AND length(login_name) BETWEEN 3 AND 63
            AND login_name NOT GLOB '*[^a-z0-9._-]*'
            AND substr(login_name, 1, 1) GLOB '[a-z0-9]'
            AND substr(login_name, -1, 1) GLOB '[a-z0-9]'
        ),
    password_hash TEXT NOT NULL
        CHECK (length(password_hash) BETWEEN 40 AND 200 AND password_hash LIKE '$argon2id$v=19$m=%'),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    password_changed_at TEXT NOT NULL
);

DROP INDEX registry_audit_events_target_idx;

ALTER TABLE registry_audit_events RENAME TO registry_audit_events_v2;

CREATE TABLE registry_audit_events (
    event_id TEXT PRIMARY KEY CHECK (length(event_id) = 36),
    actor_user_id TEXT REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    actor_type TEXT NOT NULL DEFAULT 'user' CHECK (actor_type IN ('user', 'operator')),
    actor_label TEXT,
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 120),
    target_type TEXT NOT NULL CHECK (length(target_type) BETWEEN 1 AND 80),
    target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 256),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'denied')),
    occurred_at TEXT NOT NULL,
    CHECK (
        (actor_type = 'user' AND actor_user_id IS NOT NULL AND actor_label IS NULL)
        OR (actor_type = 'operator' AND actor_user_id IS NULL AND actor_label IS NOT NULL AND length(trim(actor_label)) BETWEEN 1 AND 200)
    )
);

INSERT INTO registry_audit_events
    (event_id, actor_user_id, actor_type, actor_label, action, target_type, target_id, outcome, occurred_at)
SELECT event_id, actor_user_id, 'user', NULL, action, target_type, target_id, outcome, occurred_at
FROM registry_audit_events_v2;

DROP TABLE registry_audit_events_v2;

CREATE INDEX registry_audit_events_target_idx
    ON registry_audit_events (target_type, target_id, occurred_at);

-- +goose Down
-- Forward-only: this migration must not be rolled back automatically.
