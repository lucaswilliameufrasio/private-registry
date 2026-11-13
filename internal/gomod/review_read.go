package gomod

import (
	"context"
	"database/sql"
	"errors"
	"io"

	"private-registry/internal/storage"
)

type ReviewCandidate struct {
	ID          string
	ModulePath  string
	Version     string
	PublisherID string
	Mod         []byte
	ZipKey      storage.ObjectKey
	ZipSize     int64
}

// ListReviewCandidates exposes only pending Go receipts in the repository to
// an explicitly authorized reviewer. It does not disclose session tokens.
func (s *Service) ListReviewCandidates(ctx context.Context, reviewerID, workspaceID, repositoryID, after string, limit int) ([]ReviewCandidate, bool, error) {
	if s == nil || ctx == nil || !canonicalID(reviewerID) || !canonicalID(workspaceID) || !canonicalID(repositoryID) || (after != "" && !canonicalID(after)) || limit < 1 || limit > 100 {
		return nil, false, ErrReservationUnavailable
	}
	items := make([]ReviewCandidate, 0, limit+1)
	err := s.repositories.WithGoReviewerTransaction(ctx, reviewerID, workspaceID, repositoryID, func(tx *sql.Tx, _ string) error {
		query := `SELECT upload_session_id, module_path, version, created_by FROM registry_go_upload_sessions WHERE workspace_id = ` + s.bind(1) + ` AND repository_id = ` + s.bind(2) + ` AND status = 'uploaded' AND review_hold = 1 AND recovery_invalidated = 0 AND upload_session_id > ` + s.bind(3) + ` ORDER BY upload_session_id LIMIT ` + s.bind(4)
		rows, err := tx.QueryContext(ctx, query, workspaceID, repositoryID, after, limit+1)
		if err != nil {
			return errors.New("Go review candidates could not be listed")
		}
		defer rows.Close()
		for rows.Next() {
			var item ReviewCandidate
			if err := rows.Scan(&item.ID, &item.ModulePath, &item.Version, &item.PublisherID); err != nil {
				return errors.New("Go review candidate could not be read")
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return errors.New("Go review candidates could not be iterated")
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

// GetReviewCandidate authorizes the reviewer before reading pending metadata.
// The returned object key is internal; callers must not expose storage keys.
func (s *Service) GetReviewCandidate(ctx context.Context, reviewerID, workspaceID, repositoryID, reservationID string) (ReviewCandidate, error) {
	if s == nil || ctx == nil || !canonicalID(reviewerID) || !canonicalID(workspaceID) || !canonicalID(repositoryID) || !canonicalID(reservationID) {
		return ReviewCandidate{}, ErrReservationUnavailable
	}
	var item ReviewCandidate
	err := s.repositories.WithGoReviewerTransaction(ctx, reviewerID, workspaceID, repositoryID, func(tx *sql.Tx, _ string) error {
		query := `SELECT upload_session_id, module_path, version, created_by, mod_bytes, zip_sha256, zip_size FROM registry_go_upload_sessions WHERE upload_session_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND status = 'uploaded' AND review_hold = 1 AND recovery_invalidated = 0 AND object_verified = 1`
		var digest string
		if err := tx.QueryRowContext(ctx, query, reservationID, workspaceID, repositoryID).Scan(&item.ID, &item.ModulePath, &item.Version, &item.PublisherID, &item.Mod, &digest, &item.ZipSize); errors.Is(err, sql.ErrNoRows) {
			return ErrReservationUnavailable
		} else if err != nil {
			return errors.New("Go review candidate could not be read")
		}
		key, err := storage.NewObjectKey(workspaceID, digest)
		if err != nil || key.SHA256 != digest || item.ZipSize < 1 || item.ZipSize > s.maxZip {
			return errors.New("Go review object metadata is invalid")
		}
		item.ZipKey = key
		return nil
	})
	if err != nil {
		return ReviewCandidate{}, err
	}
	return item, nil
}

// OpenReviewZip resolves authorization and the receipt before opening storage.
func (s *Service) OpenReviewZip(ctx context.Context, reviewerID, workspaceID, repositoryID, reservationID string) (io.ReadCloser, int64, error) {
	item, err := s.GetReviewCandidate(ctx, reviewerID, workspaceID, repositoryID, reservationID)
	if err != nil {
		return nil, 0, err
	}
	reader, info, err := s.objects.Open(ctx, item.ZipKey)
	if err != nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, 0, errors.New("Go review object could not be opened")
	}
	if info.Key != item.ZipKey || info.Size != item.ZipSize {
		_ = reader.Close()
		return nil, 0, errors.New("Go review object metadata is invalid")
	}
	return reader, info.Size, nil
}
