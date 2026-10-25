-- +goose Up
CREATE TABLE registry_generic_artifact_versions (
    artifact_version_id TEXT PRIMARY KEY CHECK (length(artifact_version_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    collection_name TEXT NOT NULL CHECK (length(collection_name) BETWEEN 1 AND 128),
    version_label TEXT NOT NULL CHECK (length(version_label) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK (status IN ('receiving', 'published', 'quarantined', 'deletion_pending', 'deleted')),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    published_at TEXT,
    FOREIGN KEY (repository_id, workspace_id)
        REFERENCES registry_repositories (repository_id, workspace_id) ON DELETE RESTRICT,
    UNIQUE (repository_id, collection_name, version_label),
    UNIQUE (artifact_version_id, workspace_id, repository_id),
    CHECK (
        (status = 'receiving' AND published_at IS NULL)
        OR (status <> 'receiving' AND published_at IS NOT NULL)
    )
);

CREATE INDEX registry_generic_artifact_versions_repository_idx
    ON registry_generic_artifact_versions (workspace_id, repository_id, status, artifact_version_id);

CREATE TABLE registry_generic_upload_sessions (
    upload_session_id TEXT PRIMARY KEY CHECK (length(upload_session_id) = 36),
    artifact_version_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    path TEXT NOT NULL CHECK (length(path) BETWEEN 1 AND 1024),
    content_type TEXT NOT NULL CHECK (length(content_type) BETWEEN 1 AND 255),
    expected_size INTEGER NOT NULL CHECK (expected_size BETWEEN 0 AND 1073741824),
    expected_sha256 TEXT NOT NULL CHECK (
        length(expected_sha256) = 64
        AND expected_sha256 = lower(expected_sha256)
        AND expected_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('receiving', 'uploading', 'uploaded', 'published', 'rejected', 'expired')),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    object_sha256 TEXT,
    object_size INTEGER,
    upload_claim_id TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (artifact_version_id, workspace_id, repository_id)
        REFERENCES registry_generic_artifact_versions (artifact_version_id, workspace_id, repository_id) ON DELETE RESTRICT,
    CHECK (
        (status IN ('uploaded', 'published') AND object_sha256 IS NOT NULL AND object_size = expected_size)
        OR (status = 'rejected' AND object_sha256 IS NOT NULL AND object_size BETWEEN 0 AND 1073741824)
        OR (status NOT IN ('uploaded', 'published', 'rejected') AND object_sha256 IS NULL AND object_size IS NULL)
    ),
    CHECK (object_sha256 IS NULL OR (
        length(object_sha256) = 64
        AND object_sha256 = lower(object_sha256)
        AND object_sha256 NOT GLOB '*[^0-9a-f]*'
    )),
    CHECK (
        (status = 'uploading' AND upload_claim_id IS NOT NULL AND length(upload_claim_id) = 36)
        OR (status <> 'uploading' AND upload_claim_id IS NULL)
    )
);

CREATE UNIQUE INDEX registry_generic_upload_sessions_path_active_idx
    ON registry_generic_upload_sessions (artifact_version_id, lower(path))
    WHERE status IN ('receiving', 'uploading', 'uploaded', 'published');

CREATE INDEX registry_generic_upload_sessions_expiry_idx
    ON registry_generic_upload_sessions (status, expires_at);

CREATE TABLE registry_generic_artifact_files (
    artifact_file_id TEXT PRIMARY KEY CHECK (length(artifact_file_id) = 36),
    artifact_version_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    path TEXT NOT NULL CHECK (length(path) BETWEEN 1 AND 1024),
    content_type TEXT NOT NULL CHECK (length(content_type) BETWEEN 1 AND 255),
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 0 AND 1073741824),
    sha256 TEXT NOT NULL CHECK (
        length(sha256) = 64
        AND sha256 = lower(sha256)
        AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (artifact_version_id, workspace_id, repository_id)
        REFERENCES registry_generic_artifact_versions (artifact_version_id, workspace_id, repository_id) ON DELETE RESTRICT,
    UNIQUE (artifact_version_id, path)
);

CREATE INDEX registry_generic_artifact_files_version_idx
    ON registry_generic_artifact_files (workspace_id, repository_id, artifact_version_id, path);

-- +goose Down
-- Forward-only: artifact identities and upload receipts must not be dropped automatically.
