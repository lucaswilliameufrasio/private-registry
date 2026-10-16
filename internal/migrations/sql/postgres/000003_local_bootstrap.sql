-- +goose Up
CREATE TABLE registry_local_credentials (
    user_id TEXT PRIMARY KEY REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    login_name TEXT NOT NULL UNIQUE
        CHECK (login_name ~ '^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$'),
    password_hash TEXT NOT NULL
        CHECK (length(password_hash) BETWEEN 40 AND 200 AND password_hash LIKE '$argon2id$v=19$m=%'),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    password_changed_at TEXT NOT NULL
);

ALTER TABLE registry_audit_events
    ALTER COLUMN actor_user_id DROP NOT NULL;

ALTER TABLE registry_audit_events
    ADD COLUMN actor_type TEXT NOT NULL DEFAULT 'user'
        CHECK (actor_type IN ('user', 'operator'));

ALTER TABLE registry_audit_events
    ADD COLUMN actor_label TEXT;

ALTER TABLE registry_audit_events
    ADD CONSTRAINT registry_audit_actor_shape_check CHECK (
        (actor_type = 'user' AND actor_user_id IS NOT NULL AND actor_label IS NULL)
        OR (actor_type = 'operator' AND actor_user_id IS NULL AND actor_label IS NOT NULL AND length(trim(actor_label)) BETWEEN 1 AND 200)
    );

-- +goose Down
-- Forward-only: this migration must not be rolled back automatically.
