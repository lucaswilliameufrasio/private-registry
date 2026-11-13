// Package jobs provides the persistent claim primitives used by registry workers.
package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
)

var (
	ErrUnavailable = errors.New("job queue is unavailable")
	ErrInvalid     = errors.New("job parameters are invalid")
	ErrConflict    = errors.New("job idempotency key is already in use")
	ErrNoJob       = errors.New("no job is ready")
	ErrLease       = errors.New("job lease is no longer valid")
)

type Queue struct {
	db     *sql.DB
	driver config.DatabaseDriver
}

type Job struct {
	ID          string
	Key         string
	Kind        string
	Payload     string
	Attempts    int
	MaxAttempts int
	LeaseToken  string
	LeaseUntil  time.Time
}

func New(db *sql.DB, driver config.DatabaseDriver) (*Queue, error) {
	if db == nil || (driver != config.SQLite && driver != config.Postgres) {
		return nil, ErrUnavailable
	}
	return &Queue{db: db, driver: driver}, nil
}

// Status returns only the lifecycle state, without exposing a job payload.
func (q *Queue) Status(ctx context.Context, id string) (string, error) {
	if q == nil || q.db == nil || ctx == nil {
		return "", ErrUnavailable
	}
	if _, err := uuid.Parse(id); err != nil {
		return "", ErrInvalid
	}
	var status string
	if err := q.db.QueryRowContext(ctx, `SELECT status FROM registry_jobs WHERE job_id = `+q.bind(1), id).Scan(&status); err != nil {
		return "", errors.New("job status could not be read")
	}
	return status, nil
}

func (q *Queue) bind(n int) string {
	if q.driver == config.Postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (q *Queue) transaction(ctx context.Context, operation func(*sql.Tx) error) (err error) {
	if q == nil || q.db == nil || ctx == nil {
		return ErrUnavailable
	}
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("job transaction could not begin")
	}
	defer func() {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, errors.New("job transaction rollback failed"))
		}
	}()
	if q.driver == config.Postgres {
		var id int
		if err := tx.QueryRowContext(ctx, `SELECT singleton_id FROM registry_installation WHERE singleton_id = 1 FOR UPDATE`).Scan(&id); err != nil {
			return errors.New("job coordination lock could not be acquired")
		}
	} else {
		result, err := tx.ExecContext(ctx, `UPDATE registry_installation SET repository_visibility_policy = repository_visibility_policy WHERE singleton_id = 1`)
		if err != nil {
			return errors.New("job coordination lock could not be acquired")
		}
		if count, err := result.RowsAffected(); err != nil || count != 1 {
			return errors.New("job coordination row is unavailable")
		}
	}
	if err := operation(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("job transaction could not commit")
	}
	return nil
}

// Enqueue creates a durable job once. A repeated key with different parameters
// is rejected; payloads must not contain credentials or sensitive data.
func (q *Queue) Enqueue(ctx context.Context, key, kind, payload string, maxAttempts int, available, now time.Time) (string, error) {
	var jobID string
	err := q.transaction(ctx, func(tx *sql.Tx) error {
		var err error
		jobID, err = q.EnqueueTx(ctx, tx, key, kind, payload, maxAttempts, available, now)
		return err
	})
	if err != nil {
		return "", err
	}
	return jobID, nil
}

// EnqueueTx is Enqueue inside the caller's transaction, so a job is created
// exactly when the business change that needs it commits.
func (q *Queue) EnqueueTx(ctx context.Context, tx *sql.Tx, key, kind, payload string, maxAttempts int, available, now time.Time) (string, error) {
	if q == nil || ctx == nil || tx == nil {
		return "", ErrUnavailable
	}
	if strings.TrimSpace(key) != key || len(key) < 1 || len(key) > 200 || strings.TrimSpace(kind) != kind || len(kind) < 1 || len(kind) > 80 || len(payload) > 16384 || maxAttempts < 1 || maxAttempts > 100 || available.IsZero() || now.IsZero() {
		return "", ErrInvalid
	}
	id, err := uuid.NewV7()
	if err != nil {
		return "", errors.New("job identity could not be created")
	}
	jobID := id.String()
	query := `INSERT INTO registry_jobs (job_id, idempotency_key, kind, payload, status, attempts, max_attempts, initial_available_at_ms, available_at_ms, created_at_ms, updated_at_ms)
		VALUES (` + q.bind(1) + `,` + q.bind(2) + `,` + q.bind(3) + `,` + q.bind(4) + `,'pending',0,` + q.bind(5) + `,` + q.bind(6) + `,` + q.bind(7) + `,` + q.bind(8) + `,` + q.bind(9) + `) ON CONFLICT (idempotency_key) DO NOTHING`
	result, err := tx.ExecContext(ctx, query, jobID, key, kind, payload, maxAttempts, available.UnixMilli(), available.UnixMilli(), now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return "", errors.New("job could not be enqueued")
	}
	count, err := result.RowsAffected()
	if err != nil {
		return "", errors.New("job enqueue result could not be read")
	}
	if count == 1 {
		return jobID, nil
	}
	var storedKind, storedPayload string
	var storedMax int
	var storedAvailable int64
	query = `SELECT job_id, kind, payload, max_attempts, initial_available_at_ms FROM registry_jobs WHERE idempotency_key = ` + q.bind(1)
	if err := tx.QueryRowContext(ctx, query, key).Scan(&jobID, &storedKind, &storedPayload, &storedMax, &storedAvailable); err != nil {
		return "", errors.New("existing job could not be read")
	}
	if storedKind != kind || storedPayload != payload || storedMax != maxAttempts || storedAvailable != available.UnixMilli() {
		return "", ErrConflict
	}
	return jobID, nil
}

// Abandon ends an owned claim as dead without further attempts, for failures
// that retrying cannot fix.
func (q *Queue) Abandon(ctx context.Context, id, token string, now time.Time) error {
	if _, err := uuid.Parse(id); err != nil || now.IsZero() {
		return ErrInvalid
	}
	if _, err := uuid.Parse(token); err != nil {
		return ErrInvalid
	}
	return q.transaction(ctx, func(tx *sql.Tx) error {
		query := `UPDATE registry_jobs SET status = 'dead', lease_token = NULL, lease_until_ms = NULL, last_failure_code = 'operation_failed', revision = revision + 1, updated_at_ms = ` + q.bind(1) + ` WHERE job_id = ` + q.bind(2) + ` AND status = 'running' AND lease_token = ` + q.bind(3) + ` AND lease_until_ms > ` + q.bind(4)
		result, err := tx.ExecContext(ctx, query, now.UnixMilli(), id, token, now.UnixMilli())
		if err != nil {
			return errors.New("job could not be abandoned")
		}
		if count, err := result.RowsAffected(); err != nil {
			return errors.New("job abandonment could not be checked")
		} else if count != 1 {
			return ErrLease
		}
		return nil
	})
}

// Claim serializes selection and grants a fresh fencing token. Expired claims
// can be reclaimed; a claim always consumes one attempt.
func (q *Queue) Claim(ctx context.Context, kind string, now time.Time, duration time.Duration) (Job, error) {
	if strings.TrimSpace(kind) != kind || len(kind) == 0 || len(kind) > 80 || now.IsZero() || duration < time.Second || duration > 24*time.Hour {
		return Job{}, ErrInvalid
	}
	var job Job
	found := false
	err := q.transaction(ctx, func(tx *sql.Tx) error {
		// Limit cleanup per call so many exhausted leases cannot monopolize the lock.
		for i := 0; i < 32; i++ {
			query := `SELECT job_id, idempotency_key, kind, payload, attempts, max_attempts FROM registry_jobs
				WHERE kind = ` + q.bind(1) + ` AND recovery_previous_status IS NULL AND ((status = 'pending' AND available_at_ms <= ` + q.bind(2) + `)
				OR (status = 'running' AND lease_until_ms <= ` + q.bind(3) + `)) ORDER BY available_at_ms, job_id LIMIT 1`
			err := tx.QueryRowContext(ctx, query, kind, now.UnixMilli(), now.UnixMilli()).Scan(&job.ID, &job.Key, &job.Kind, &job.Payload, &job.Attempts, &job.MaxAttempts)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return errors.New("ready job could not be read")
			}
			if job.Attempts >= job.MaxAttempts {
				query = `UPDATE registry_jobs SET status = 'dead', lease_token = NULL, lease_until_ms = NULL, last_failure_code = 'lease_expired', revision = revision + 1, updated_at_ms = ` + q.bind(1) + ` WHERE job_id = ` + q.bind(2)
				if _, err := tx.ExecContext(ctx, query, now.UnixMilli(), job.ID); err != nil {
					return errors.New("exhausted job could not be recorded")
				}
				continue
			}
			token, err := uuid.NewRandom()
			if err != nil {
				return errors.New("job lease token could not be generated")
			}
			job.LeaseToken = token.String()
			job.LeaseUntil = now.Add(duration).UTC()
			job.Attempts++
			query = `UPDATE registry_jobs SET last_failure_code = CASE WHEN status = 'running' THEN 'lease_expired' ELSE last_failure_code END, status = 'running', attempts = ` + q.bind(1) + `, lease_token = ` + q.bind(2) + `, lease_until_ms = ` + q.bind(3) + `, revision = revision + 1, updated_at_ms = ` + q.bind(4) + ` WHERE job_id = ` + q.bind(5)
			if _, err := tx.ExecContext(ctx, query, job.Attempts, job.LeaseToken, job.LeaseUntil.UnixMilli(), now.UnixMilli(), job.ID); err != nil {
				return errors.New("job claim could not be recorded")
			}
			found = true
			return nil
		}
		return nil
	})
	if err != nil {
		return Job{}, err
	}
	if !found {
		return Job{}, ErrNoJob
	}
	return job, nil
}

// Finish transitions an owned, unexpired claim to success, retry, or dead.
// next is required for retries; the caller supplies the bounded backoff policy.
func (q *Queue) Finish(ctx context.Context, id, token string, success bool, now, next time.Time) error {
	if _, err := uuid.Parse(id); err != nil || now.IsZero() {
		return ErrInvalid
	}
	if _, err := uuid.Parse(token); err != nil || (!success && (next.IsZero() || next.Before(now))) {
		return ErrInvalid
	}
	return q.transaction(ctx, func(tx *sql.Tx) error {
		var attempts, maxAttempts int
		query := `SELECT attempts, max_attempts FROM registry_jobs WHERE job_id = ` + q.bind(1) + ` AND status = 'running' AND lease_token = ` + q.bind(2) + ` AND lease_until_ms > ` + q.bind(3)
		if err := tx.QueryRowContext(ctx, query, id, token, now.UnixMilli()).Scan(&attempts, &maxAttempts); errors.Is(err, sql.ErrNoRows) {
			return ErrLease
		} else if err != nil {
			return errors.New("job lease could not be checked")
		}
		status := "succeeded"
		available := now.UnixMilli()
		var failureCode any
		if !success {
			failureCode = "operation_failed"
			status = "pending"
			available = next.UnixMilli()
			if attempts >= maxAttempts {
				status = "dead"
			}
		}
		query = `UPDATE registry_jobs SET status = ` + q.bind(1) + `, available_at_ms = ` + q.bind(2) + `, lease_token = NULL, lease_until_ms = NULL, last_failure_code = ` + q.bind(3) + `, revision = revision + 1, updated_at_ms = ` + q.bind(4) + ` WHERE job_id = ` + q.bind(5)
		if _, err := tx.ExecContext(ctx, query, status, available, failureCode, now.UnixMilli(), id); err != nil {
			return errors.New("job completion could not be recorded")
		}
		return nil
	})
}

// Reschedule completes a recurring job and atomically prepares its next run.
// It may be called only while the current lease is valid. Attempts reset for
// the new run; the original idempotency record remains unchanged.
func (q *Queue) Reschedule(ctx context.Context, id, token string, now, next time.Time) error {
	if _, err := uuid.Parse(id); err != nil || now.IsZero() || next.IsZero() || next.UnixMilli() <= now.UnixMilli() {
		return ErrInvalid
	}
	if _, err := uuid.Parse(token); err != nil {
		return ErrInvalid
	}
	return q.transaction(ctx, func(tx *sql.Tx) error {
		query := `UPDATE registry_jobs SET status = 'pending', attempts = 0, available_at_ms = ` + q.bind(1) +
			`, lease_token = NULL, lease_until_ms = NULL, last_failure_code = NULL, revision = revision + 1, updated_at_ms = ` + q.bind(2) +
			` WHERE job_id = ` + q.bind(3) + ` AND status = 'running' AND lease_token = ` + q.bind(4) + ` AND lease_until_ms > ` + q.bind(5)
		result, err := tx.ExecContext(ctx, query, next.UnixMilli(), now.UnixMilli(), id, token, now.UnixMilli())
		if err != nil {
			return errors.New("recurring job could not be rescheduled")
		}
		count, err := result.RowsAffected()
		if err != nil {
			return errors.New("recurring job result could not be checked")
		}
		if count != 1 {
			return ErrLease
		}
		return nil
	})
}

// Heartbeat extends only a current, unexpired lease, without shortening it.
func (q *Queue) Heartbeat(ctx context.Context, id, token string, now time.Time, duration time.Duration) error {
	if _, err := uuid.Parse(id); err != nil || now.IsZero() || duration < time.Second || duration > 24*time.Hour {
		return ErrInvalid
	}
	if _, err := uuid.Parse(token); err != nil {
		return ErrInvalid
	}
	return q.transaction(ctx, func(tx *sql.Tx) error {
		var leaseUntil int64
		query := `SELECT lease_until_ms FROM registry_jobs WHERE job_id = ` + q.bind(1) + ` AND status = 'running' AND lease_token = ` + q.bind(2) + ` AND lease_until_ms > ` + q.bind(3)
		if err := tx.QueryRowContext(ctx, query, id, token, now.UnixMilli()).Scan(&leaseUntil); errors.Is(err, sql.ErrNoRows) {
			return ErrLease
		} else if err != nil {
			return errors.New("job lease could not be checked")
		}
		until := now.Add(duration).UnixMilli()
		if until <= leaseUntil {
			return nil
		}
		query = `UPDATE registry_jobs SET lease_until_ms = ` + q.bind(1) + `, revision = revision + 1, updated_at_ms = ` + q.bind(2) + ` WHERE job_id = ` + q.bind(3)
		if _, err := tx.ExecContext(ctx, query, until, now.UnixMilli(), id); err != nil {
			return errors.New("job heartbeat could not be recorded")
		}
		return nil
	})
}
