package oci

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/repositories"
)

var (
	ErrReviewPending = errors.New("OCI manifest is waiting for human review")
	ErrReviewUnknown = errors.New("OCI review is unknown or already decided")
	ErrSelfReview    = errors.New("OCI manifest cannot be reviewed by its submitter")
	ErrReviewStale   = errors.New("OCI review can no longer be published")
)

// Review is one pending or decided submission.
type Review struct {
	ID          string
	Digest      string
	MediaType   string
	Image       string
	Tag         string
	Status      string
	SubmittedBy string
	SubmittedAt time.Time
	Size        int
}

func (s *Service) reviewRequired(ctx context.Context, tx *sql.Tx, workspace, repository string) (bool, error) {
	var required int
	if err := tx.QueryRowContext(ctx, `SELECT review_required FROM registry_repositories WHERE workspace_id = `+s.bind(1)+` AND repository_id = `+s.bind(2), workspace, repository).Scan(&required); err != nil {
		return false, ErrUnavailable
	}
	return required == 1, nil
}

// queueReview records a submission. A repeated push of the same manifest to
// the same tag keeps the existing pending entry.
func (s *Service) queueReview(ctx context.Context, tx *sql.Tx, user, workspace, repository, image, tag, digest, mediaType string, body []byte) error {
	var tagValue any
	if tag != "" {
		tagValue = tag
	}
	var exists bool
	query := `SELECT EXISTS (SELECT 1 FROM registry_oci_reviews WHERE repository_id = ` + s.bind(1) + ` AND digest = ` + s.bind(2) + ` AND image_name = ` + s.bind(3) + ` AND COALESCE(tag, '') = ` + s.bind(4) + ` AND status = 'pending')`
	if err := tx.QueryRowContext(ctx, query, repository, digest, image, tag).Scan(&exists); err != nil {
		return ErrUnavailable
	}
	if exists {
		return nil
	}
	// The pending document counts against quota like a published one, so a
	// review queue cannot be used to store unlimited content.
	if err := s.checkQuota(ctx, tx, workspace, repository, int64(len(body))); err != nil {
		return err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return ErrUnavailable
	}
	insert := `INSERT INTO registry_oci_reviews (review_id, repository_id, workspace_id, digest, media_type, content, image_name, tag, status, submitted_by, submitted_at_ms) VALUES (` + s.binds(8) + `, 'pending', ` + s.bind(9) + `, ` + s.bind(10) + `)`
	if _, err := tx.ExecContext(ctx, insert, id.String(), repository, workspace, digest, mediaType, body, image, tagValue, user, time.Now().UTC().UnixMilli()); err != nil {
		return ErrUnavailable
	}
	return repositories.RecordAudit(ctx, tx, s.driver, user, "oci_review.submitted", "oci_review", id.String())
}

// ListReviews returns pending submissions for workspace managers.
func (s *Service) ListReviews(ctx context.Context, actor, workspace, repository string) ([]Review, error) {
	var reviews []Review
	err := s.repos.WithRepositoryManagerTransaction(ctx, actor, workspace, repository, repositories.FormatOCI, func(tx *sql.Tx, _ string) error {
		rows, err := tx.QueryContext(ctx, `SELECT review_id, digest, media_type, image_name, COALESCE(tag, ''), status, submitted_by, submitted_at_ms, LENGTH(content) FROM registry_oci_reviews WHERE repository_id = `+s.bind(1)+` AND status = 'pending' ORDER BY review_id LIMIT 200`, repository)
		if err != nil {
			return ErrUnavailable
		}
		defer rows.Close()
		for rows.Next() {
			var review Review
			var submitted int64
			if err := rows.Scan(&review.ID, &review.Digest, &review.MediaType, &review.Image, &review.Tag, &review.Status, &review.SubmittedBy, &submitted, &review.Size); err != nil {
				return ErrUnavailable
			}
			review.SubmittedAt = time.UnixMilli(submitted).UTC()
			reviews = append(reviews, review)
		}
		return rows.Err()
	})
	return reviews, err
}

// ReviewManifest returns the submitted document so a reviewer can inspect it.
func (s *Service) ReviewManifest(ctx context.Context, actor, workspace, repository, reviewID string) (Manifest, error) {
	var manifest Manifest
	err := s.repos.WithRepositoryManagerTransaction(ctx, actor, workspace, repository, repositories.FormatOCI, func(tx *sql.Tx, _ string) error {
		err := tx.QueryRowContext(ctx, `SELECT digest, media_type, content FROM registry_oci_reviews WHERE review_id = `+s.bind(1)+` AND repository_id = `+s.bind(2)+` AND status = 'pending'`, reviewID, repository).Scan(&manifest.Digest, &manifest.MediaType, &manifest.Content)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrReviewUnknown
		} else if err != nil {
			return ErrUnavailable
		}
		return nil
	})
	return manifest, err
}

// DecideReview approves or rejects a pending submission. Approval publishes
// the manifest and moves its tag in the same transaction, after checking
// again that the submitter still holds the publisher grant, that everything
// referenced is still in the repository and that the tag rules still allow
// it. The submitter can never decide on their own submission.
func (s *Service) DecideReview(ctx context.Context, actor, workspace, repository, reviewID string, approve bool) error {
	if _, err := uuid.Parse(reviewID); err != nil {
		return ErrReviewUnknown
	}
	return s.repos.WithRepositoryManagerTransaction(ctx, actor, workspace, repository, repositories.FormatOCI, func(tx *sql.Tx, user string) error {
		var digest, mediaType, image, tag, submitter string
		var body []byte
		err := tx.QueryRowContext(ctx, `SELECT digest, media_type, content, image_name, COALESCE(tag, ''), submitted_by FROM registry_oci_reviews WHERE review_id = `+s.bind(1)+` AND repository_id = `+s.bind(2)+` AND status = 'pending'`, reviewID, repository).Scan(&digest, &mediaType, &body, &image, &tag, &submitter)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrReviewUnknown
		} else if err != nil {
			return ErrUnavailable
		}
		if submitter == user {
			return ErrSelfReview
		}
		status, action := "rejected", "oci_review.rejected"
		if approve {
			status, action = "approved", "oci_review.approved"
			var publisher bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_repository_grants g JOIN registry_users u ON u.user_id = g.user_id WHERE g.user_id = `+s.bind(1)+` AND g.workspace_id = `+s.bind(2)+` AND g.repository_id = `+s.bind(3)+` AND g.role = 'publisher' AND g.revoked_at IS NULL AND u.status = 'active')`, submitter, workspace, repository).Scan(&publisher); err != nil {
				return ErrUnavailable
			}
			if !publisher {
				return ErrReviewStale
			}
			_, blobs, children, err := parseManifest(body, mediaType)
			if err != nil {
				return ErrReviewStale
			}
			if err := s.requireReferences(ctx, tx, repository, blobs, children); err != nil {
				if errors.Is(err, ErrManifestBlob) {
					return ErrReviewStale
				}
				return err
			}
			var known bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_oci_manifests WHERE repository_id = `+s.bind(1)+` AND digest = `+s.bind(2)+`)`, repository, digest).Scan(&known); err != nil {
				return ErrUnavailable
			}
			if err := s.commitManifest(ctx, tx, submitter, workspace, repository, image, tag, digest, mediaType, body, blobs, children, known); err != nil {
				return err
			}
		}
		result, err := tx.ExecContext(ctx, `UPDATE registry_oci_reviews SET status = `+s.bind(1)+`, decided_by = `+s.bind(2)+`, decided_at_ms = `+s.bind(3)+` WHERE review_id = `+s.bind(4)+` AND status = 'pending'`, status, user, time.Now().UTC().UnixMilli(), reviewID)
		if err != nil {
			return ErrUnavailable
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return ErrReviewUnknown
		}
		return repositories.RecordAudit(ctx, tx, s.driver, user, action, "oci_review", reviewID)
	})
}

// blobReadable reports whether a reader may fetch a blob. While review is
// required, only blobs that a published manifest references can be read, so
// knowing the digest of content still under review does not expose it.
func (s *Service) blobReadable(ctx context.Context, workspace, repository, digest string) (bool, error) {
	var required int
	if err := s.db.QueryRowContext(ctx, `SELECT review_required FROM registry_repositories WHERE workspace_id = `+s.bind(1)+` AND repository_id = `+s.bind(2), workspace, repository).Scan(&required); err != nil {
		return false, ErrUnavailable
	}
	if required == 0 {
		return true, nil
	}
	var referenced bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_oci_manifest_references WHERE repository_id = `+s.bind(1)+` AND referenced_digest = `+s.bind(2)+` AND kind = 'blob')`, repository, digest).Scan(&referenced); err != nil {
		return false, ErrUnavailable
	}
	return referenced, nil
}

// StatReadableBlob is StatBlob for readers: under review, unpublished blobs
// are reported as unknown.
func (s *Service) StatReadableBlob(ctx context.Context, workspace, repository, digest string) (int64, error) {
	size, err := s.StatBlob(ctx, repository, digest)
	if err != nil {
		return 0, err
	}
	readable, err := s.blobReadable(ctx, workspace, repository, digest)
	if err != nil {
		return 0, err
	}
	if !readable {
		return 0, ErrBlobUnknown
	}
	return size, nil
}
