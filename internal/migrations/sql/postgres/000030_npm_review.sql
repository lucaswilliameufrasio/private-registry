-- +goose Up
CREATE UNIQUE INDEX registry_npm_reservation_scope_idx ON registry_npm_reservations (reservation_id, workspace_id, repository_id);
CREATE TABLE registry_npm_reviewer_grants (
    grant_id TEXT PRIMARY KEY CHECK (length(grant_id) = 36),
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_format TEXT NOT NULL DEFAULT 'npm' CHECK (repository_format = 'npm'),
    user_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_by TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    granted_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (repository_id, workspace_id, repository_format) REFERENCES registry_repositories (repository_id, workspace_id, format) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX registry_npm_reviewer_active_idx ON registry_npm_reviewer_grants (repository_id, user_id) WHERE revoked_at IS NULL;
-- +goose StatementBegin
CREATE FUNCTION registry_npm_reviewer_grant_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'npm reviewer grant history is immutable';
    END IF;
    IF NEW.grant_id IS DISTINCT FROM OLD.grant_id OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.repository_id IS DISTINCT FROM OLD.repository_id OR NEW.repository_format IS DISTINCT FROM OLD.repository_format OR NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.granted_by IS DISTINCT FROM OLD.granted_by OR NEW.granted_at IS DISTINCT FROM OLD.granted_at OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
        RAISE EXCEPTION 'npm reviewer grant identity and revocation are immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_npm_reviewer_grant_immutable BEFORE UPDATE OR DELETE ON registry_npm_reviewer_grants FOR EACH ROW EXECUTE FUNCTION registry_npm_reviewer_grant_immutable();
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION registry_npm_reviewer_membership_inactive() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status = 'active' AND NEW.status <> 'active' THEN
        UPDATE registry_npm_reviewer_grants SET revoked_at = NEW.updated_at WHERE workspace_id = NEW.workspace_id AND user_id = NEW.user_id AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_npm_reviewer_membership_inactive AFTER UPDATE OF status ON registry_workspace_memberships FOR EACH ROW EXECUTE FUNCTION registry_npm_reviewer_membership_inactive();
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION registry_npm_reviewer_user_inactive() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status = 'active' AND NEW.status <> 'active' THEN
        UPDATE registry_npm_reviewer_grants SET revoked_at = NEW.updated_at WHERE user_id = NEW.user_id AND revoked_at IS NULL;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER registry_npm_reviewer_user_inactive AFTER UPDATE OF status ON registry_users FOR EACH ROW EXECUTE FUNCTION registry_npm_reviewer_user_inactive();
-- +goose StatementEnd
CREATE TABLE registry_npm_review_decisions (
    decision_id TEXT PRIMARY KEY CHECK (length(decision_id) = 36),
    reservation_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    reviewer_id TEXT NOT NULL REFERENCES registry_users (user_id) ON DELETE RESTRICT,
    reviewer_grant_id TEXT NOT NULL REFERENCES registry_npm_reviewer_grants (grant_id) ON DELETE RESTRICT,
    publisher_grant_id TEXT REFERENCES registry_repository_grants (grant_id) ON DELETE RESTRICT,
    policy_revision BIGINT NOT NULL CHECK (policy_revision >= 0),
    decision_sequence BIGINT NOT NULL CHECK (decision_sequence > 0),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reason TEXT,
    decided_at TEXT NOT NULL,
    FOREIGN KEY (reservation_id, workspace_id, repository_id) REFERENCES registry_npm_reservations (reservation_id, workspace_id, repository_id) ON DELETE RESTRICT,
    UNIQUE (reservation_id, decision_sequence),
    CHECK ((decision = 'approved' AND reason IS NULL AND publisher_grant_id IS NOT NULL) OR (decision = 'rejected' AND reason IS NOT NULL AND length(trim(reason)) BETWEEN 1 AND 1000))
);
CREATE INDEX registry_npm_review_reservation_idx ON registry_npm_review_decisions (reservation_id, decision_sequence);
-- +goose StatementBegin
CREATE FUNCTION registry_npm_review_decision_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'npm review decisions are immutable';
END;
$$;
CREATE TRIGGER registry_npm_review_decision_immutable BEFORE UPDATE OR DELETE ON registry_npm_review_decisions FOR EACH ROW EXECUTE FUNCTION registry_npm_review_decision_immutable();
-- +goose StatementEnd
-- +goose Down
-- Forward-only: reviewer and decision history must not be discarded.
