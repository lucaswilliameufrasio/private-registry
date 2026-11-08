package cargo

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"private-registry/internal/repositories"
)

var ErrReviewUnavailable = errors.New("Cargo review is unavailable")

// DecideReview records one immutable human decision. It never publishes a
// crate. A future HTTP caller must require a browser session, recent MFA and
// CSRF and must not expose archive content without reviewer authorization.
func (s *ReservationService) DecideReview(ctx context.Context, reviewer, workspace, repository, reservationID, decision, reason string) (string, error) {
	if s == nil || ctx == nil || (decision != "approved" && decision != "rejected") {
		return "", ErrReviewUnavailable
	}
	id, err := uuid.Parse(reservationID)
	if err != nil || id.String() != reservationID {
		return "", ErrReviewUnavailable
	}
	if decision == "approved" && reason != "" {
		return "", ErrReviewUnavailable
	}
	if decision == "rejected" && (strings.TrimSpace(reason) == "" || len(reason) > 1000 || !utf8.ValidString(reason)) {
		return "", ErrReviewUnavailable
	}
	var result string
	err = s.repositories.WithCargoReviewerTransaction(ctx, reviewer, workspace, repository, func(tx *sql.Tx, reviewerGrant string) error {
		query := `SELECT r.created_by, r.status, r.review_hold, r.recovery_invalidated, r.object_verified, p.review_revision, t.publisher_grant_id FROM registry_cargo_reservations r JOIN registry_repositories p ON p.repository_id = r.repository_id AND p.workspace_id = r.workspace_id JOIN registry_cargo_write_tokens t ON t.token_id = r.token_id WHERE r.reservation_id = ` + s.bind(1) + ` AND r.workspace_id = ` + s.bind(2) + ` AND r.repository_id = ` + s.bind(3)
		var publisher, status, publisherGrant string
		var hold, invalidated, verified int
		var revision int64
		if err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository).Scan(&publisher, &status, &hold, &invalidated, &verified, &revision, &publisherGrant); errors.Is(err, sql.ErrNoRows) {
			return ErrReviewUnavailable
		} else if err != nil {
			return errors.New("Cargo review receipt could not be read")
		}
		if publisher == reviewer || status != "uploaded" || hold != 1 || invalidated != 0 || verified != 1 {
			return ErrReviewUnavailable
		}
		query = `SELECT decision_id, decision, reviewer_grant_id, publisher_grant_id, policy_revision, decision_sequence FROM registry_cargo_review_decisions WHERE reservation_id = ` + s.bind(1) + ` ORDER BY decision_sequence DESC LIMIT 1`
		var lastID, lastDecision, lastReviewerGrant string
		var lastPublisherGrant sql.NullString
		var lastRevision, sequence int64
		var identicalApproval bool
		err := tx.QueryRowContext(ctx, query, reservationID).Scan(&lastID, &lastDecision, &lastReviewerGrant, &lastPublisherGrant, &lastRevision, &sequence)
		if err == nil {
			if lastDecision == "rejected" {
				return ErrReviewUnavailable
			}
			if decision == "approved" && lastDecision == "approved" && lastReviewerGrant == reviewerGrant && lastPublisherGrant.Valid && lastPublisherGrant.String == publisherGrant && lastRevision == revision {
				identicalApproval = true
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return errors.New("Cargo review history could not be read")
		}
		if sequence == math.MaxInt64 {
			return errors.New("Cargo review sequence is exhausted")
		}
		sequence++
		var publisherGrantValue any
		var reasonValue any
		if decision == "approved" {
			query = `SELECT EXISTS (SELECT 1 FROM registry_repository_grants g JOIN registry_users u ON u.user_id = g.user_id JOIN registry_workspace_memberships m ON m.user_id = g.user_id AND m.workspace_id = g.workspace_id WHERE g.grant_id = ` + s.bind(1) + ` AND g.user_id = ` + s.bind(2) + ` AND g.workspace_id = ` + s.bind(3) + ` AND g.repository_id = ` + s.bind(4) + ` AND g.role = 'publisher' AND g.revoked_at IS NULL AND u.status = 'active' AND m.status = 'active')`
			var allowed bool
			if err := tx.QueryRowContext(ctx, query, publisherGrant, publisher, workspace, repository).Scan(&allowed); err != nil {
				return errors.New("Cargo publisher grant could not be checked")
			}
			if !allowed {
				return ErrReviewUnavailable
			}
			if identicalApproval {
				result = lastID
				return nil
			}
			publisherGrantValue = publisherGrant
		} else {
			reasonValue = reason
		}
		id, err := uuid.NewV7()
		if err != nil {
			return errors.New("Cargo review identity could not be created")
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		query = `INSERT INTO registry_cargo_review_decisions (decision_id, reservation_id, workspace_id, repository_id, reviewer_id, reviewer_grant_id, publisher_grant_id, policy_revision, decision_sequence, decision, reason, decided_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `, ` + s.bind(7) + `, ` + s.bind(8) + `, ` + s.bind(9) + `, ` + s.bind(10) + `, ` + s.bind(11) + `, ` + s.bind(12) + `)`
		if _, err := tx.ExecContext(ctx, query, id.String(), reservationID, workspace, repository, reviewer, reviewerGrant, publisherGrantValue, revision, sequence, decision, reasonValue, now); err != nil {
			return errors.New("Cargo review decision could not be recorded")
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Cargo review audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'user', ` + s.bind(3) + `, 'cargo_reservation', ` + s.bind(4) + `, 'succeeded', ` + s.bind(5) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), reviewer, "cargo.review."+decision, reservationID, now); err != nil {
			return errors.New("Cargo review decision could not be audited")
		}
		result = id.String()
		return nil
	})
	if err != nil {
		return "", err
	}
	return result, nil
}

// RequireCurrentApproval must run under the same coordinated transaction as
// authorization and the future publication mutation. It does not authenticate
// a bearer or authorize the caller. Rejects stale grants and policy revisions.
func (s *ReservationService) RequireCurrentApproval(ctx context.Context, tx *sql.Tx, workspace, repository, reservationID, publisher string) error {
	if s == nil || ctx == nil || tx == nil {
		return ErrReviewUnavailable
	}
	query := `SELECT r.review_hold, p.review_required FROM registry_cargo_reservations r JOIN registry_repositories p ON p.repository_id = r.repository_id AND p.workspace_id = r.workspace_id WHERE r.reservation_id = ` + s.bind(1) + ` AND r.workspace_id = ` + s.bind(2) + ` AND r.repository_id = ` + s.bind(3) + ` AND r.created_by = ` + s.bind(4) + ` AND r.status = 'uploaded' AND r.object_verified = 1 AND r.recovery_invalidated = 0`
	var hold, required int
	if err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository, publisher).Scan(&hold, &required); errors.Is(err, sql.ErrNoRows) {
		return ErrReviewUnavailable
	} else if err != nil {
		return errors.New("Cargo review state could not be read")
	}
	if hold == 0 && required == 0 {
		return nil
	}
	if hold != 1 {
		return repositories.ErrReviewRequired
	}
	query = `SELECT EXISTS (SELECT 1 FROM registry_cargo_review_decisions d JOIN registry_cargo_reservations r ON r.reservation_id = d.reservation_id AND r.workspace_id = d.workspace_id AND r.repository_id = d.repository_id JOIN registry_repositories p ON p.repository_id = r.repository_id AND p.workspace_id = r.workspace_id JOIN registry_cargo_write_tokens t ON t.token_id = r.token_id JOIN registry_cargo_reviewer_grants rg ON rg.grant_id = d.reviewer_grant_id AND rg.user_id = d.reviewer_id AND rg.workspace_id = d.workspace_id AND rg.repository_id = d.repository_id JOIN registry_repository_grants pg ON pg.grant_id = d.publisher_grant_id AND pg.grant_id = t.publisher_grant_id AND pg.user_id = r.created_by AND pg.workspace_id = r.workspace_id AND pg.repository_id = r.repository_id JOIN registry_users reviewer ON reviewer.user_id = d.reviewer_id JOIN registry_workspace_memberships m ON m.user_id = d.reviewer_id AND m.workspace_id = d.workspace_id WHERE d.reservation_id = ` + s.bind(1) + ` AND d.workspace_id = ` + s.bind(2) + ` AND d.repository_id = ` + s.bind(3) + ` AND r.created_by = ` + s.bind(4) + ` AND d.decision = 'approved' AND d.decision_sequence = (SELECT MAX(decision_sequence) FROM registry_cargo_review_decisions WHERE reservation_id = r.reservation_id) AND d.reviewer_id <> r.created_by AND d.policy_revision = p.review_revision AND rg.revoked_at IS NULL AND pg.revoked_at IS NULL AND pg.role = 'publisher' AND reviewer.status = 'active' AND m.status = 'active')`
	var approved bool
	if err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository, publisher).Scan(&approved); err != nil {
		return errors.New("Cargo review approval could not be checked")
	}
	if !approved {
		return repositories.ErrReviewRequired
	}
	return nil
}
