-- +goose Up
CREATE TABLE registry_workspace_invitations (
    invitation_id TEXT PRIMARY KEY CHECK (length(invitation_id) = 36),
    workspace_id TEXT NOT NULL REFERENCES registry_workspaces (workspace_id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (role IN ('administrator', 'member')),
    token_sha256 TEXT NOT NULL CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > created_at_ms),
    redeemed_at_ms BIGINT,
    redeemed_by TEXT REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    revoked_at_ms BIGINT,
    CHECK ((redeemed_at_ms IS NULL) = (redeemed_by IS NULL))
);
CREATE INDEX registry_workspace_invitations_workspace_idx ON registry_workspace_invitations (workspace_id, invitation_id);

CREATE TABLE registry_oci_reviews (
    review_id TEXT PRIMARY KEY CHECK (length(review_id) = 36),
    repository_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'oci' CHECK (repository_format = 'oci'),
    digest TEXT NOT NULL CHECK (length(digest) = 71),
    media_type TEXT NOT NULL CHECK (length(media_type) BETWEEN 1 AND 255),
    content BYTEA NOT NULL,
    image_name TEXT NOT NULL CHECK (length(image_name) BETWEEN 1 AND 180),
    tag TEXT CHECK (tag IS NULL OR length(tag) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    submitted_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    submitted_at_ms BIGINT NOT NULL,
    decided_by TEXT REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    decided_at_ms BIGINT,
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT,
    CHECK ((status = 'pending') = (decided_by IS NULL)),
    CHECK (decided_by IS NULL OR decided_by <> submitted_by)
);
CREATE INDEX registry_oci_reviews_repository_idx ON registry_oci_reviews (repository_id, status, review_id);
CREATE UNIQUE INDEX registry_oci_reviews_pending_idx ON registry_oci_reviews (repository_id, digest, image_name, COALESCE(tag, '')) WHERE status = 'pending';

-- +goose Down
-- Forward-only: invitation and review decisions are audit evidence.
