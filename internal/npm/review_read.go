package npm

import (
	"context"
	"database/sql"
	"errors"
	"io"

	"github.com/google/uuid"
	"private-registry/internal/storage"
)

type ReviewCandidate struct {
	ID          string
	Name        string
	Version     string
	PublisherID string
}

// OpenReviewArchive checks reviewer authority before opening storage. The
// caller must bound transfers; revocation cannot retract already delivered data.
func (s *ReceiptService) OpenReviewArchive(ctx context.Context, reviewer, workspace, repository, reservationID string) (io.ReadCloser, int64, error) {
	if s == nil || ctx == nil {
		return nil, 0, ErrReviewUnavailable
	}
	id, err := uuid.Parse(reservationID)
	if err != nil || id.String() != reservationID {
		return nil, 0, ErrReviewUnavailable
	}
	var digest string
	var size int64
	err = s.repositories.WithNPMReviewerTransaction(ctx, reviewer, workspace, repository, func(tx *sql.Tx, _ string) error {
		query := `SELECT r.tarball_sha256, r.tarball_size FROM registry_npm_reservations r WHERE r.reservation_id = ` + s.bind(1) + ` AND r.workspace_id = ` + s.bind(2) + ` AND r.repository_id = ` + s.bind(3) + ` AND r.status = 'uploaded' AND r.object_verified = 1 AND r.review_hold = 1 AND r.recovery_invalidated = 0 AND NOT EXISTS (SELECT 1 FROM registry_npm_review_decisions d WHERE d.reservation_id = r.reservation_id AND d.decision = 'rejected')`
		if err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository).Scan(&digest, &size); errors.Is(err, sql.ErrNoRows) {
			return ErrReviewUnavailable
		} else if err != nil {
			return errors.New("npm review archive metadata could not be read")
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	key, err := storage.NewObjectKey(workspace, digest)
	if err != nil || key.SHA256 != digest || size < 1 || size > s.options.Limits.MaxCompressedBytes {
		return nil, 0, errors.New("npm review archive metadata is invalid")
	}
	reader, info, err := s.objects.Open(ctx, key)
	if err != nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, 0, errors.New("npm review archive could not be opened")
	}
	if info.Key != key || info.Size != size {
		_ = reader.Close()
		return nil, 0, errors.New("npm review archive metadata differs")
	}
	return reader, size, nil
}

// ListReviewCandidates requires a current reviewer grant and returns only
// verified held receipts not rejected or invalidated; it does not publish.
func (s *ReservationService) ListReviewCandidates(ctx context.Context, reviewer, workspace, repository, after string, limit int) ([]ReviewCandidate, bool, error) {
	if s == nil || ctx == nil || limit < 1 || limit > 100 {
		return nil, false, ErrReviewUnavailable
	}
	if after != "" {
		id, err := uuid.Parse(after)
		if err != nil || id.String() != after {
			return nil, false, ErrReviewUnavailable
		}
	}
	items := make([]ReviewCandidate, 0, limit+1)
	err := s.repositories.WithNPMReviewerTransaction(ctx, reviewer, workspace, repository, func(tx *sql.Tx, _ string) error {
		query := `SELECT r.reservation_id, r.name, r.version, r.created_by FROM registry_npm_reservations r WHERE r.workspace_id = ` + s.bind(1) + ` AND r.repository_id = ` + s.bind(2) + ` AND r.status = 'uploaded' AND r.object_verified = 1 AND r.review_hold = 1 AND r.recovery_invalidated = 0 AND r.reservation_id > ` + s.bind(3) + ` AND NOT EXISTS (SELECT 1 FROM registry_npm_review_decisions d WHERE d.reservation_id = r.reservation_id AND d.decision = 'rejected') ORDER BY r.reservation_id LIMIT ` + s.bind(4)
		rows, err := tx.QueryContext(ctx, query, workspace, repository, after, limit+1)
		if err != nil {
			return errors.New("npm review candidates could not be listed")
		}
		defer rows.Close()
		for rows.Next() {
			var item ReviewCandidate
			if err := rows.Scan(&item.ID, &item.Name, &item.Version, &item.PublisherID); err != nil {
				return errors.New("npm review candidate could not be read")
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return errors.New("npm review candidates could not be iterated")
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	return items, more, nil
}
