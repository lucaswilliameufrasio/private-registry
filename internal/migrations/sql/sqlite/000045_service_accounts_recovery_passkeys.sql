-- +goose Up
-- A service account is a registry user that cannot sign in. It belongs to
-- one workspace, receives grants like any member and only ever authenticates
-- with registry tokens.
CREATE TABLE registry_service_accounts (
    user_id TEXT PRIMARY KEY REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    workspace_id TEXT NOT NULL REFERENCES registry_workspaces (workspace_id) ON DELETE RESTRICT,
    description TEXT NOT NULL CHECK (length(description) BETWEEN 1 AND 200),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL
);
CREATE INDEX registry_service_accounts_workspace_idx ON registry_service_accounts (workspace_id, user_id);

-- Trust between a CI identity and a service account of one repository.
CREATE TABLE registry_trusted_publishers (
    publisher_id TEXT PRIMARY KEY CHECK (length(publisher_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    service_account_id TEXT NOT NULL REFERENCES registry_service_accounts (user_id) ON DELETE RESTRICT,
    provider TEXT NOT NULL CHECK (provider IN ('github')),
    subject_repository TEXT NOT NULL CHECK (length(subject_repository) BETWEEN 3 AND 200),
    subject_repository_id TEXT,
    subject_ref TEXT NOT NULL CHECK (length(subject_ref) BETWEEN 1 AND 255),
    subject_environment TEXT CHECK (subject_environment IS NULL OR length(subject_environment) BETWEEN 1 AND 255),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL,
    revoked_at_ms INTEGER,
    FOREIGN KEY (repository_id, workspace_id) REFERENCES registry_repositories (repository_id, workspace_id) ON DELETE RESTRICT
);
CREATE INDEX registry_trusted_publishers_repository_idx ON registry_trusted_publishers (repository_id, revoked_at_ms);

-- Each CI identity token is exchanged at most once.
CREATE TABLE registry_trusted_publishing_tokens (
    token_id TEXT PRIMARY KEY CHECK (length(token_id) BETWEEN 1 AND 255),
    provider TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL
);
CREATE INDEX registry_trusted_publishing_tokens_expiry_idx ON registry_trusted_publishing_tokens (expires_at_ms);

CREATE TABLE registry_password_resets (
    reset_id TEXT PRIMARY KEY CHECK (length(reset_id) = 36),
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    token_sha256 TEXT NOT NULL CHECK (length(token_sha256) = 64),
    reset_mfa INTEGER NOT NULL CHECK (reset_mfa IN (0, 1)),
    created_by TEXT REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > created_at_ms),
    used_at_ms INTEGER,
    revoked_at_ms INTEGER
);
CREATE INDEX registry_password_resets_user_idx ON registry_password_resets (user_id, reset_id);

CREATE TABLE registry_webauthn_credentials (
    credential_id TEXT PRIMARY KEY CHECK (length(credential_id) BETWEEN 16 AND 1400),
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    credential BLOB NOT NULL,
    sign_count INTEGER NOT NULL CHECK (sign_count >= 0),
    created_at_ms INTEGER NOT NULL,
    last_used_at_ms INTEGER
);
CREATE INDEX registry_webauthn_credentials_user_idx ON registry_webauthn_credentials (user_id);

-- +goose Down
-- Forward-only: credentials and recovery records are audit evidence.
