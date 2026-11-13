package gomod

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/repositories"
)

// ApproveReservation records a review by a distinct active reviewer. It does
// not publish the version. Policy or capability changes invalidate the
// approval at publication time and require a new review.
func (s *Service) ApproveReservation(ctx context.Context, reviewerID, workspaceID, repositoryID, reservationID string) error {
	if s == nil || ctx == nil || !canonicalID(reviewerID) || !canonicalID(workspaceID) || !canonicalID(repositoryID) || !canonicalID(reservationID) {
		return ErrReservationUnavailable
	}
	return s.repositories.WithGoReviewerTransaction(ctx, reviewerID, workspaceID, repositoryID, func(tx *sql.Tx, grantID string) error {
		query := `SELECT u.created_by, u.status, u.review_hold, u.recovery_invalidated, r.review_revision, u.reviewed_by, u.review_grant_id, u.review_publisher_grant_id, u.reviewed_policy_revision FROM registry_go_upload_sessions u JOIN registry_repositories r ON r.repository_id = u.repository_id AND r.workspace_id = u.workspace_id WHERE u.upload_session_id = ` + s.bind(1) + ` AND u.workspace_id = ` + s.bind(2) + ` AND u.repository_id = ` + s.bind(3)
		var publisherID, status string
		var hold, invalidated int
		var revision int64
		var oldReviewer, oldGrant, oldPublisherGrant sql.NullString
		var oldRevision sql.NullInt64
		if err := tx.QueryRowContext(ctx, query, reservationID, workspaceID, repositoryID).Scan(&publisherID, &status, &hold, &invalidated, &revision, &oldReviewer, &oldGrant, &oldPublisherGrant, &oldRevision); errors.Is(err, sql.ErrNoRows) {
			return ErrReservationUnavailable
		} else if err != nil {
			return errors.New("Go review candidate could not be read")
		}
		if status != "uploaded" || hold != 1 || invalidated != 0 || publisherID == reviewerID {
			return repositories.ErrForbidden
		}
		query = `SELECT g.grant_id FROM registry_users u JOIN registry_workspace_memberships m ON m.user_id = u.user_id JOIN registry_repository_grants g ON g.user_id = u.user_id AND g.workspace_id = m.workspace_id WHERE u.user_id = ` + s.bind(1) + ` AND u.status = 'active' AND m.workspace_id = ` + s.bind(2) + ` AND m.status = 'active' AND g.repository_id = ` + s.bind(3) + ` AND g.role = 'publisher' AND g.revoked_at IS NULL`
		var publisherGrantID string
		if err := tx.QueryRowContext(ctx, query, publisherID, workspaceID, repositoryID).Scan(&publisherGrantID); errors.Is(err, sql.ErrNoRows) {
			return repositories.ErrForbidden
		} else if err != nil {
			return errors.New("Go publisher eligibility could not be checked")
		}
		if oldReviewer.Valid && oldGrant.Valid && oldPublisherGrant.Valid && oldRevision.Valid && oldReviewer.String == reviewerID && oldGrant.String == grantID && oldPublisherGrant.String == publisherGrantID && oldRevision.Int64 == revision {
			return nil
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		query = `UPDATE registry_go_upload_sessions SET reviewed_by = ` + s.bind(1) + `, review_grant_id = ` + s.bind(2) + `, review_publisher_grant_id = ` + s.bind(3) + `, reviewed_policy_revision = ` + s.bind(4) + `, reviewed_at = ` + s.bind(5) + ` WHERE upload_session_id = ` + s.bind(6) + ` AND status = 'uploaded' AND review_hold = 1 AND recovery_invalidated = 0`
		result, err := tx.ExecContext(ctx, query, reviewerID, grantID, publisherGrantID, revision, now, reservationID)
		if err != nil {
			return errors.New("Go review could not be recorded")
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return ErrReservationUnavailable
		}
		decisionID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Go review decision identity could not be created")
		}
		query = `INSERT INTO registry_go_review_decisions (decision_id, upload_session_id, reviewer_id, grant_id, publisher_grant_id, policy_revision, decision, reason, decided_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `, 'approved', NULL, ` + s.bind(7) + `)`
		if _, err := tx.ExecContext(ctx, query, decisionID.String(), reservationID, reviewerID, grantID, publisherGrantID, revision, now); err != nil {
			return errors.New("Go review decision could not be recorded")
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Go review audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'go.upload.approved', 'go_upload', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), reviewerID, reservationID, now); err != nil {
			return errors.New("Go review could not be audited")
		}
		return nil
	})
}

// RejectReservation records a reasoned review decision and releases quota and
// identity without deleting the verified object or its historical reference.
func (s *Service) RejectReservation(ctx context.Context, reviewerID, workspaceID, repositoryID, reservationID, reason string) error {
	if s == nil || ctx == nil || !canonicalID(reviewerID) || !canonicalID(workspaceID) || !canonicalID(repositoryID) || !canonicalID(reservationID) {
		return ErrReservationUnavailable
	}
	reason = strings.TrimSpace(reason)
	if len(reason) < 1 || len(reason) > 1000 {
		return ErrInvalidPublication
	}
	return s.repositories.WithGoReviewerTransaction(ctx, reviewerID, workspaceID, repositoryID, func(tx *sql.Tx, grantID string) error {
		query := `SELECT u.created_by, u.status, u.review_hold, u.recovery_invalidated, r.review_revision FROM registry_go_upload_sessions u JOIN registry_repositories r ON r.repository_id = u.repository_id AND r.workspace_id = u.workspace_id WHERE u.upload_session_id = ` + s.bind(1) + ` AND u.workspace_id = ` + s.bind(2) + ` AND u.repository_id = ` + s.bind(3)
		var publisherID, status string
		var hold, invalidated int
		var revision int64
		if err := tx.QueryRowContext(ctx, query, reservationID, workspaceID, repositoryID).Scan(&publisherID, &status, &hold, &invalidated, &revision); errors.Is(err, sql.ErrNoRows) {
			return ErrReservationUnavailable
		} else if err != nil {
			return errors.New("Go review candidate could not be read")
		}
		if publisherID == reviewerID || hold != 1 || invalidated != 0 {
			return repositories.ErrForbidden
		}
		if status == "rejected" {
			query = `SELECT EXISTS (SELECT 1 FROM registry_go_review_decisions WHERE upload_session_id = ` + s.bind(1) + ` AND reviewer_id = ` + s.bind(2) + ` AND grant_id = ` + s.bind(3) + ` AND decision = 'rejected' AND reason = ` + s.bind(4) + `)`
			var same bool
			if err := tx.QueryRowContext(ctx, query, reservationID, reviewerID, grantID, reason).Scan(&same); err != nil {
				return errors.New("Go rejection could not be checked")
			}
			if same {
				return nil
			}
			return ErrReservationUnavailable
		}
		if status != "uploaded" {
			return ErrReservationUnavailable
		}
		query = `UPDATE registry_go_upload_sessions SET status = 'rejected' WHERE upload_session_id = ` + s.bind(1) + ` AND status = 'uploaded' AND review_hold = 1 AND recovery_invalidated = 0`
		result, err := tx.ExecContext(ctx, query, reservationID)
		if err != nil {
			return errors.New("Go rejection could not be recorded")
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return ErrReservationUnavailable
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		decisionID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Go rejection decision identity could not be created")
		}
		query = `INSERT INTO registry_go_review_decisions (decision_id, upload_session_id, reviewer_id, grant_id, policy_revision, decision, reason, decided_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, 'rejected', ` + s.bind(6) + `, ` + s.bind(7) + `)`
		if _, err := tx.ExecContext(ctx, query, decisionID.String(), reservationID, reviewerID, grantID, revision, reason, now); err != nil {
			return errors.New("Go rejection decision could not be recorded")
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Go rejection audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'go.upload.rejected', 'go_upload', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), reviewerID, reservationID, now); err != nil {
			return errors.New("Go rejection could not be audited")
		}
		return nil
	})
}

func (s *Service) requireValidReview(ctx context.Context, tx *sql.Tx, workspaceID, repositoryID, reservationID, publisherID string, held int) error {
	query := `SELECT review_required FROM registry_repositories WHERE workspace_id = ` + s.bind(1) + ` AND repository_id = ` + s.bind(2)
	var required int
	if err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&required); err != nil {
		return errors.New("Go review policy could not be checked")
	}
	if held == 0 {
		if required != 0 {
			return repositories.ErrReviewRequired
		}
		return nil
	}
	query = `SELECT EXISTS (SELECT 1 FROM registry_go_upload_sessions u JOIN registry_repositories r ON r.repository_id = u.repository_id AND r.workspace_id = u.workspace_id JOIN registry_go_reviewer_grants g ON g.grant_id = u.review_grant_id AND g.user_id = u.reviewed_by AND g.repository_id = u.repository_id AND g.workspace_id = u.workspace_id JOIN registry_repository_grants pg ON pg.grant_id = u.review_publisher_grant_id AND pg.user_id = u.created_by AND pg.repository_id = u.repository_id AND pg.workspace_id = u.workspace_id AND pg.role = 'publisher' JOIN registry_users reviewer ON reviewer.user_id = u.reviewed_by JOIN registry_workspace_memberships m ON m.user_id = u.reviewed_by AND m.workspace_id = u.workspace_id WHERE u.upload_session_id = ` + s.bind(1) + ` AND u.workspace_id = ` + s.bind(2) + ` AND u.repository_id = ` + s.bind(3) + ` AND u.reviewed_by <> ` + s.bind(4) + ` AND u.reviewed_policy_revision = r.review_revision AND g.revoked_at IS NULL AND pg.revoked_at IS NULL AND reviewer.status = 'active' AND m.status = 'active')`
	var valid bool
	if err := tx.QueryRowContext(ctx, query, reservationID, workspaceID, repositoryID, publisherID).Scan(&valid); err != nil {
		return errors.New("Go review eligibility could not be checked")
	}
	if !valid {
		return repositories.ErrReviewRequired
	}
	return nil
}
