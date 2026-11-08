package cargo

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

// OpenReviewArchive checks the current reviewer grant and receipt before
// opening storage. Once opened, the caller must bound the transfer; revocation
// cannot retract bytes already delivered or interrupt an in-progress stream.
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
	err = s.repositories.WithCargoReviewerTransaction(ctx, reviewer, workspace, repository, func(tx *sql.Tx, _ string) error {
		query := `SELECT r.archive_sha256, r.archive_size FROM registry_cargo_reservations r WHERE r.reservation_id = ` + s.bind(1) + ` AND r.workspace_id = ` + s.bind(2) + ` AND r.repository_id = ` + s.bind(3) + ` AND r.status = 'uploaded' AND r.object_verified = 1 AND r.review_hold = 1 AND r.recovery_invalidated = 0 AND NOT EXISTS (SELECT 1 FROM registry_cargo_review_decisions d WHERE d.reservation_id = r.reservation_id AND d.decision = 'rejected')`
		if err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository).Scan(&digest, &size); errors.Is(err, sql.ErrNoRows) {
			return ErrReviewUnavailable
		} else if err != nil {
			return errors.New("Cargo review archive metadata could not be read")
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	key, err := storage.NewObjectKey(workspace, digest)
	if err != nil || key.SHA256 != digest || size < 1 || size > s.options.Limits.MaxCompressedBytes {
		return nil, 0, errors.New("Cargo review archive metadata is invalid")
	}
	reader, info, err := s.objects.Open(ctx, key)
	if err != nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, 0, errors.New("Cargo review archive could not be opened")
	}
	if info.Key != key || info.Size != size {
		_ = reader.Close()
		return nil, 0, errors.New("Cargo review archive metadata differs")
	}
	return reader, size, nil
}

// ListReviewCandidates requires an explicit current reviewer grant and returns
// only verified, held receipts which have not been rejected or invalidated.
// It does not grant access to their archives or publish them.
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
	err := s.repositories.WithCargoReviewerTransaction(ctx, reviewer, workspace, repository, func(tx *sql.Tx, _ string) error {
		query := `SELECT r.reservation_id, r.name, r.version, r.created_by FROM registry_cargo_reservations r WHERE r.workspace_id = ` + s.bind(1) + ` AND r.repository_id = ` + s.bind(2) + ` AND r.status = 'uploaded' AND r.object_verified = 1 AND r.review_hold = 1 AND r.recovery_invalidated = 0 AND r.reservation_id > ` + s.bind(3) + ` AND NOT EXISTS (SELECT 1 FROM registry_cargo_review_decisions d WHERE d.reservation_id = r.reservation_id AND d.decision = 'rejected') ORDER BY r.reservation_id LIMIT ` + s.bind(4)
		rows, err := tx.QueryContext(ctx, query, workspace, repository, after, limit+1)
		if err != nil {
			return errors.New("Cargo review candidates could not be listed")
		}
		defer rows.Close()
		for rows.Next() {
			var item ReviewCandidate
			if err := rows.Scan(&item.ID, &item.Name, &item.Version, &item.PublisherID); err != nil {
				return errors.New("Cargo review candidate could not be read")
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return errors.New("Cargo review candidates could not be iterated")
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
