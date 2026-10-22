-- +goose Up
CREATE TABLE registry_repository_grants (
    grant_id TEXT PRIMARY KEY CHECK (length(grant_id) = 36),
    repository_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (role IN ('reader', 'publisher', 'maintainer', 'security')),
    granted_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by TEXT REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    revocation_reason TEXT CHECK (revocation_reason IN ('manual', 'membership_inactive')),
    FOREIGN KEY (repository_id, workspace_id)
        REFERENCES registry_repositories (repository_id, workspace_id) ON DELETE RESTRICT,
    CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL AND revocation_reason IS NULL)
        OR (
            revoked_at IS NOT NULL
            AND (
                (revocation_reason = 'manual' AND revoked_by IS NOT NULL)
                OR (revocation_reason = 'membership_inactive' AND revoked_by IS NULL)
            )
        )
    )
);

CREATE UNIQUE INDEX registry_repository_grants_active_unique_idx
    ON registry_repository_grants (repository_id, user_id, role)
    WHERE revoked_at IS NULL;

CREATE INDEX registry_repository_grants_workspace_user_idx
    ON registry_repository_grants (workspace_id, user_id, revoked_at, repository_id, role);

CREATE INDEX registry_repository_grants_repository_idx
    ON registry_repository_grants (workspace_id, repository_id, revoked_at, user_id, role);

-- +goose StatementBegin
CREATE TRIGGER registry_repository_grants_membership_inactive
AFTER UPDATE OF status ON registry_workspace_memberships
WHEN OLD.status = 'active' AND NEW.status <> 'active'
BEGIN
    UPDATE registry_repository_grants
    SET revoked_at = NEW.updated_at,
        revocation_reason = 'membership_inactive'
    WHERE workspace_id = NEW.workspace_id
        AND user_id = NEW.user_id
        AND revoked_at IS NULL;
END;
-- +goose StatementEnd

-- +goose Down
-- Forward-only: grants and their revocation history must not be dropped automatically.
