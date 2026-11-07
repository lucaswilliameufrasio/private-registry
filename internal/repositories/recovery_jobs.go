package repositories

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"
)

var ErrRecoveryJobConflict = errors.New("recovery job state or revision has changed")

type RecoveryJob struct {
	ID             string
	Kind           string
	PreviousStatus string
	Attempts       int
	MaxAttempts    int
	Revision       int64
	UpdatedAt      time.Time
}

// ListRecoveryJobs returns operational metadata without job payloads or leases.
func (s *Service) ListRecoveryJobs(ctx context.Context, actorUserID, after string, pageSize int) ([]RecoveryJob, bool, error) {
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
	items := make([]RecoveryJob, 0, pageSize+1)
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveAdministrator(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		query := `SELECT job_id, kind, recovery_previous_status, attempts, max_attempts, revision, updated_at_ms FROM registry_jobs WHERE recovery_previous_status IS NOT NULL AND job_id > ` + bind(s.driver, 1) + ` ORDER BY job_id LIMIT ` + bind(s.driver, 2)
		rows, err := tx.QueryContext(ctx, query, after, pageSize+1)
		if err != nil {
			return errors.New("recovery jobs could not be listed")
		}
		defer rows.Close()
		for rows.Next() {
			var job RecoveryJob
			var updated int64
			if err := rows.Scan(&job.ID, &job.Kind, &job.PreviousStatus, &job.Attempts, &job.MaxAttempts, &job.Revision, &updated); err != nil {
				return errors.New("recovery job record could not be read")
			}
			if job.Kind != "expire-generic-uploads" {
				job.Kind = "other"
			}
			job.UpdatedAt = time.UnixMilli(updated).UTC()
			items = append(items, job)
		}
		if err := rows.Err(); err != nil {
			return errors.New("recovery jobs could not be iterated")
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

// ReleaseRecoveryJob requeues only the idempotent upload-expiration job after
// explicit operator confirmation. Other kinds require their own recovery policy.
func (s *Service) ReleaseRecoveryJob(ctx context.Context, actorUserID, jobID string, expectedRevision int64) error {
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
		query := `UPDATE registry_jobs SET recovery_previous_status = NULL, attempts = 0, available_at_ms = ` + bind(s.driver, 1) + `, updated_at_ms = ` + bind(s.driver, 2) + `, revision = revision + 1 WHERE job_id = ` + bind(s.driver, 3) + ` AND kind = 'expire-generic-uploads' AND status = 'pending' AND recovery_previous_status IS NOT NULL AND revision = ` + bind(s.driver, 4)
		result, err := tx.ExecContext(ctx, query, now, now, jobID, expectedRevision)
		if err != nil {
			return errors.New("recovery job could not be released")
		}
		count, err := result.RowsAffected()
		if err != nil {
			return errors.New("recovery job release result could not be checked")
		}
		if count != 1 {
			return ErrRecoveryJobConflict
		}
		return recordAudit(ctx, tx, s.driver, actorID, "job.recovery.released", "job", jobID)
	})
}
