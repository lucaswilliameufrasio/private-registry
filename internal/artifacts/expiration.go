package artifacts

import (
	"context"
	"errors"
	"time"
)

const maxExpirationBatch = 256

// ExpireUploadBatch reconciles a bounded batch of expired, unfinished uploads.
// It never deletes objects: storage orphan collection requires its own grace
// period and coordination with publication and backup.
func (s *Service) ExpireUploadBatch(ctx context.Context, now time.Time, limit int) (int, error) {
	if s == nil || s.db == nil || ctx == nil {
		return 0, errors.New("artifact expiration service is unavailable")
	}
	if now.IsZero() || limit < 1 || limit > maxExpirationBatch {
		return 0, errors.New("artifact expiration time or batch size is invalid")
	}
	// RFC3339Nano omits trailing fractional zeroes, so lexical order within a
	// second is not chronological. A one-second conservative cutoff avoids
	// expiring early and still lets the existing expiry index bound each scan.
	cutoff := now.UTC().Add(-time.Second).Format(time.RFC3339Nano)
	query := `SELECT upload_session_id, expires_at FROM registry_generic_upload_sessions
		WHERE status IN ('receiving', 'uploading') AND expires_at < ` + bind(s.driver, 1) + `
		ORDER BY expires_at, upload_session_id LIMIT ` + bind(s.driver, 2)
	rows, err := s.db.QueryContext(ctx, query, cutoff, limit)
	if err != nil {
		return 0, errors.New("artifact expiration candidates could not be read")
	}
	type candidate struct{ id, expiry string }
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.expiry); err != nil {
			_ = rows.Close()
			return 0, errors.New("artifact expiration candidate is invalid")
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, errors.New("artifact expiration candidates could not be iterated")
	}
	if err := rows.Close(); err != nil {
		return 0, errors.New("artifact expiration candidates could not be closed")
	}
	count := 0
	for _, item := range candidates {
		expiry, err := time.Parse(time.RFC3339Nano, item.expiry)
		if err != nil {
			return count, errors.New("artifact expiration candidate has an invalid expiry")
		}
		if now.Before(expiry) {
			continue
		}
		update := `UPDATE registry_generic_upload_sessions SET status = 'expired', upload_claim_id = NULL, updated_at = ` + bind(s.driver, 1) +
			` WHERE upload_session_id = ` + bind(s.driver, 2) + ` AND expires_at = ` + bind(s.driver, 3) + ` AND status IN ('receiving', 'uploading')`
		result, err := s.db.ExecContext(ctx, update, now.UTC().Format(time.RFC3339Nano), item.id, item.expiry)
		if err != nil {
			return count, errors.New("artifact expiration could not be recorded")
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return count, errors.New("artifact expiration result could not be checked")
		}
		count += int(changed)
	}
	return count, nil
}
