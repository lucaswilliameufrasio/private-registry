package cargo

import (
	"context"
	"errors"
	"time"
)

// ExpireUploadBatch expires at most limit stale reservations. It does not
// delete files or objects and can be retried after interruption. A scheduler
// must call it; this primitive alone is not a durable maintenance worker.
func (s *ReservationService) ExpireUploadBatch(ctx context.Context, now time.Time, limit int) (int, error) {
	if s == nil || s.db == nil || ctx == nil || now.IsZero() || limit < 1 || limit > 256 {
		return 0, errors.New("Cargo reservation expiration parameters are invalid")
	}
	query := `SELECT reservation_id, expires_at_ms FROM registry_cargo_reservations WHERE status IN ('reserved', 'uploading') AND expires_at_ms <= ` + s.bind(1) + ` ORDER BY expires_at_ms, reservation_id LIMIT ` + s.bind(2)
	rows, err := s.db.QueryContext(ctx, query, now.UTC().UnixMilli(), limit)
	if err != nil {
		return 0, errors.New("Cargo reservation expiration candidates could not be read")
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
			return 0, errors.New("Cargo reservation expiration candidate is invalid")
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, errors.New("Cargo reservation expiration candidates could not be iterated")
	}
	if err := rows.Close(); err != nil {
		return 0, errors.New("Cargo reservation expiration candidates could not be closed")
	}
	count := 0
	for _, item := range candidates {
		query := `UPDATE registry_cargo_reservations SET status = 'expired', upload_claim_id = NULL WHERE reservation_id = ` + s.bind(1) + ` AND expires_at_ms = ` + s.bind(2) + ` AND status IN ('reserved', 'uploading')`
		result, err := s.db.ExecContext(ctx, query, item.id, item.expires)
		if err != nil {
			return count, errors.New("Cargo reservation expiration could not be recorded")
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return count, errors.New("Cargo reservation expiration result could not be checked")
		}
		count += int(changed)
	}
	return count, nil
}
