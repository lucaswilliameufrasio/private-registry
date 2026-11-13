package repositories

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"
)

var (
	ErrInvalidJobCursor  = errors.New("job cursor is invalid")
	ErrInvalidJobRequest = errors.New("job retry request is invalid")
	ErrDeadJobConflict   = errors.New("dead job state or revision has changed")
)

type DeadJob struct {
	ID          string
	Kind        string
	Attempts    int
	MaxAttempts int
	FailureCode string
	Revision    int64
	UpdatedAt   time.Time
}

// ListDeadJobs exposes bounded operational metadata, not payloads, idempotency
// keys, lease tokens, or package identities, to active installation admins.
func (s *Service) ListDeadJobs(ctx context.Context, actorUserID, after string, pageSize int) ([]DeadJob, bool, error) {
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return nil, false, ErrUnauthenticated
	}
	if after != "" {
		after, err = parseUUID(after, ErrInvalidJobCursor)
		if err != nil {
			return nil, false, ErrInvalidJobCursor
		}
	}
	if pageSize < 1 || pageSize > 100 {
		return nil, false, ErrInvalidJobRequest
	}
	items := make([]DeadJob, 0, pageSize+1)
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveAdministrator(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		query := `SELECT job_id, kind, attempts, max_attempts, last_failure_code, revision, updated_at_ms FROM registry_jobs WHERE status = 'dead' AND job_id > ` + bind(s.driver, 1) + ` ORDER BY job_id LIMIT ` + bind(s.driver, 2)
		rows, err := tx.QueryContext(ctx, query, after, pageSize+1)
		if err != nil {
			return errors.New("dead jobs could not be listed")
		}
		defer rows.Close()
		for rows.Next() {
			var job DeadJob
			var code sql.NullString
			var updated int64
			if err := rows.Scan(&job.ID, &job.Kind, &job.Attempts, &job.MaxAttempts, &code, &job.Revision, &updated); err != nil {
				return errors.New("dead job record could not be read")
			}
			if job.Kind != "expire-generic-uploads" {
				job.Kind = "other"
			}
			job.FailureCode = "unknown"
			if code.Valid {
				job.FailureCode = code.String
			}
			job.UpdatedAt = time.UnixMilli(updated).UTC()
			items = append(items, job)
		}
		if err := rows.Err(); err != nil {
			return errors.New("dead jobs could not be iterated")
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	hasMore := len(items) > pageSize
	if hasMore {
		items = items[:pageSize]
	}
	return items, hasMore, nil
}

// RetryDeadJob only requeues the exact observed revision of the explicitly
// approved maintenance kind. Future job kinds need their own retry policy.
// An old operator view cannot requeue a job that failed again (ABA).
func (s *Service) RetryDeadJob(ctx context.Context, actorUserID, jobID string, expectedRevision int64) error {
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return ErrUnauthenticated
	}
	jobID, err = parseUUID(jobID, ErrInvalidJobRequest)
	if err != nil || expectedRevision < 0 || expectedRevision == math.MaxInt64 {
		return ErrInvalidJobRequest
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveAdministrator(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		now := time.Now().UTC().UnixMilli()
		query := `UPDATE registry_jobs SET status = 'pending', attempts = 0, available_at_ms = ` + bind(s.driver, 1) + `, updated_at_ms = ` + bind(s.driver, 2) + `, revision = revision + 1 WHERE job_id = ` + bind(s.driver, 3) + ` AND kind = 'expire-generic-uploads' AND status = 'dead' AND revision = ` + bind(s.driver, 4)
		result, err := tx.ExecContext(ctx, query, now, now, jobID, expectedRevision)
		if err != nil {
			return errors.New("dead job could not be retried")
		}
		count, err := result.RowsAffected()
		if err != nil {
			return errors.New("dead job retry result could not be checked")
		}
		if count != 1 {
			return ErrDeadJobConflict
		}
		return recordAudit(ctx, tx, s.driver, actorID, "job.dead_letter.retried", "job", jobID)
	})
}
