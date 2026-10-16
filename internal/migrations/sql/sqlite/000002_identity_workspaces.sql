-- +goose Up
ALTER TABLE registry_installation
    ADD COLUMN signup_policy TEXT NOT NULL DEFAULT 'closed'
        CHECK (signup_policy IN ('closed', 'invitations', 'open'));

ALTER TABLE registry_installation
    ADD COLUMN workspace_creation_policy TEXT NOT NULL DEFAULT 'admin_only'
        CHECK (workspace_creation_policy IN ('admin_only', 'authorized_users', 'any_user'));

CREATE TABLE registry_users (
    user_id TEXT PRIMARY KEY CHECK (length(user_id) = 36),
    display_name TEXT NOT NULL CHECK (length(trim(display_name)) BETWEEN 1 AND 200),
    email TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deprovisioned')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX registry_users_status_idx ON registry_users (status, user_id);

CREATE TABLE registry_external_identities (
    external_identity_id TEXT PRIMARY KEY CHECK (length(external_identity_id) = 36),
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    provider_id TEXT NOT NULL CHECK (length(trim(provider_id)) BETWEEN 1 AND 200),
    issuer TEXT NOT NULL CHECK (length(trim(issuer)) BETWEEN 1 AND 2048),
    subject TEXT NOT NULL CHECK (length(trim(subject)) BETWEEN 1 AND 1024),
    created_at TEXT NOT NULL,
    UNIQUE (provider_id, issuer, subject)
);

CREATE INDEX registry_external_identities_user_idx
    ON registry_external_identities (user_id, provider_id);

CREATE TABLE registry_instance_admins (
    user_id TEXT PRIMARY KEY REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_by TEXT REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_at TEXT NOT NULL
);

CREATE TABLE registry_workspace_creation_grants (
    user_id TEXT PRIMARY KEY REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE registry_workspaces (
    workspace_id TEXT PRIMARY KEY CHECK (length(workspace_id) = 36),
    slug TEXT NOT NULL UNIQUE CHECK (slug = lower(slug)),
    display_name TEXT NOT NULL CHECK (length(trim(display_name)) BETWEEN 1 AND 200),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deletion_pending', 'deleted')),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    deleted_at TEXT
);

-- +goose StatementBegin
CREATE TRIGGER registry_workspaces_slug_immutable
BEFORE UPDATE OF slug ON registry_workspaces
WHEN NEW.slug <> OLD.slug
BEGIN
    SELECT RAISE(ABORT, 'workspace slug is immutable');
END;
-- +goose StatementEnd

CREATE TABLE registry_workspace_memberships (
    workspace_id TEXT NOT NULL REFERENCES registry_workspaces (workspace_id) ON DELETE RESTRICT,
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (role IN ('owner', 'administrator', 'member')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'removed')),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (workspace_id, user_id)
);

CREATE INDEX registry_workspace_memberships_user_idx
    ON registry_workspace_memberships (user_id, status, workspace_id);

CREATE TABLE registry_audit_events (
    event_id TEXT PRIMARY KEY CHECK (length(event_id) = 36),
    actor_user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 120),
    target_type TEXT NOT NULL CHECK (length(target_type) BETWEEN 1 AND 80),
    target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 256),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'denied')),
    occurred_at TEXT NOT NULL
);

CREATE INDEX registry_audit_events_target_idx
    ON registry_audit_events (target_type, target_id, occurred_at);

-- +goose Down
-- Forward-only: this migration must not be rolled back automatically.
