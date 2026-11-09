-- +goose Up
CREATE UNIQUE INDEX registry_pub_reservation_scope_idx ON registry_pub_reservations (reservation_id, workspace_id, repository_id);
CREATE TABLE registry_pub_reviewer_grants (
    grant_id TEXT PRIMARY KEY CHECK (length(grant_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'pub' CHECK (repository_format = 'pub'),
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX registry_pub_reviewer_active_idx ON registry_pub_reviewer_grants (repository_id, user_id) WHERE revoked_at IS NULL;
-- +goose StatementBegin
CREATE TRIGGER registry_pub_reviewer_grant_immutable BEFORE UPDATE ON registry_pub_reviewer_grants
WHEN NEW.grant_id <> OLD.grant_id OR NEW.workspace_id <> OLD.workspace_id OR NEW.repository_id <> OLD.repository_id OR NEW.repository_format <> OLD.repository_format OR NEW.user_id <> OLD.user_id OR NEW.granted_by <> OLD.granted_by OR NEW.granted_at <> OLD.granted_at OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
BEGIN
    SELECT RAISE(ABORT, 'pub reviewer grant identity and revocation are immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_pub_reviewer_grant_no_delete BEFORE DELETE ON registry_pub_reviewer_grants
BEGIN
    SELECT RAISE(ABORT, 'pub reviewer grant history is immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_pub_reviewer_membership_inactive AFTER UPDATE OF status ON registry_workspace_memberships
WHEN OLD.status = 'active' AND NEW.status <> 'active'
BEGIN
    UPDATE registry_pub_reviewer_grants SET revoked_at = NEW.updated_at WHERE workspace_id = NEW.workspace_id AND user_id = NEW.user_id AND revoked_at IS NULL;
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_pub_reviewer_user_inactive AFTER UPDATE OF status ON registry_users
WHEN OLD.status = 'active' AND NEW.status <> 'active'
BEGIN
    UPDATE registry_pub_reviewer_grants SET revoked_at = NEW.updated_at WHERE user_id = NEW.user_id AND revoked_at IS NULL;
END;
-- +goose StatementEnd
CREATE TABLE registry_pub_review_decisions (
    decision_id TEXT PRIMARY KEY CHECK (length(decision_id) = 36),
    reservation_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    reviewer_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    reviewer_grant_id TEXT NOT NULL REFERENCES registry_pub_reviewer_grants (grant_id) ON DELETE RESTRICT,
    publisher_grant_id TEXT REFERENCES registry_repository_grants (grant_id) ON DELETE RESTRICT,
    policy_revision INTEGER NOT NULL CHECK (policy_revision >= 0),
    decision_sequence INTEGER NOT NULL CHECK (decision_sequence > 0),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reason TEXT,
    decided_at TEXT NOT NULL,
    FOREIGN KEY (reservation_id, workspace_id, repository_id) REFERENCES registry_pub_reservations (reservation_id, workspace_id, repository_id) ON DELETE RESTRICT,
    UNIQUE (reservation_id, decision_sequence),
    CHECK ((decision = 'approved' AND reason IS NULL AND publisher_grant_id IS NOT NULL) OR (decision = 'rejected' AND reason IS NOT NULL AND length(trim(reason)) BETWEEN 1 AND 1000))
);
CREATE INDEX registry_pub_review_reservation_idx ON registry_pub_review_decisions (reservation_id, decision_sequence);
-- +goose StatementBegin
CREATE TRIGGER registry_pub_review_decision_no_update BEFORE UPDATE ON registry_pub_review_decisions
BEGIN
    SELECT RAISE(ABORT, 'pub review decisions are immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER registry_pub_review_decision_no_delete BEFORE DELETE ON registry_pub_review_decisions
BEGIN
    SELECT RAISE(ABORT, 'pub review decisions are immutable');
END;
-- +goose StatementEnd
-- +goose Down
-- Forward-only: reviewer and decision history must not be discarded.
