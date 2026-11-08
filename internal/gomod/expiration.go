package gomod

import (
	"context"
	"errors"
	"time"
)

// ExpireUploadBatch fences a bounded set of expired, unfinished sessions. It
// never removes objects or expires verified uploads awaiting review.
func (s *Service) ExpireUploadBatch(ctx context.Context, now time.Time, limit int) (int, error) {
	if s == nil || s.db == nil || ctx == nil || now.IsZero() || limit < 1 || limit > 256 {
		return 0, errors.New("Go upload expiration parameters are invalid")
	}
	query := `SELECT upload_session_id, expires_at_ms FROM registry_go_upload_sessions WHERE status IN ('receiving', 'uploading') AND expires_at_ms <= ` + s.bind(1) + ` ORDER BY expires_at_ms, upload_session_id LIMIT ` + s.bind(2)
	rows, err := s.db.QueryContext(ctx, query, now.UTC().UnixMilli(), limit)
	if err != nil {
		return 0, errors.New("Go upload expiration candidates could not be read")
	}
	type candidate struct {
		id      string
		expires int64
	}
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.expires); err != nil {
			_ = rows.Close()
			return 0, errors.New("Go upload expiration candidate is invalid")
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, errors.New("Go upload expiration candidates could not be iterated")
	}
	if err := rows.Close(); err != nil {
		return 0, errors.New("Go upload expiration candidates could not be closed")
	}
	count := 0
	for _, item := range candidates {
		query := `UPDATE registry_go_upload_sessions SET status = 'expired', upload_claim_id = NULL WHERE upload_session_id = ` + s.bind(1) + ` AND expires_at_ms = ` + s.bind(2) + ` AND status IN ('receiving', 'uploading')`
		result, err := s.db.ExecContext(ctx, query, item.id, item.expires)
		if err != nil {
			return count, errors.New("Go upload expiration could not be recorded")
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return count, errors.New("Go upload expiration result could not be checked")
		}
		count += int(changed)
	}
	return count, nil
}
