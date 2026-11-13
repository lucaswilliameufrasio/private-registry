package email

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/jobs"
)

var (
	ErrFailureUnknown = errors.New("this email is not a failed delivery that can be resent")
)

// Failure is one email that was given up on and not resent yet. The
// recipient is masked: administrators need to recognize it, not read it.
type Failure struct {
	JobID     string
	Template  Template
	Provider  string
	Error     string
	Recipient string
	Attempts  int
	FailedAt  time.Time
}

// Status summarizes the outbox for monitoring.
type Status struct {
	Provider string
	Pending  int
	// OldestPending is the creation time of the oldest message still waiting.
	OldestPending time.Time
	Failed        int
}

func (o *Outbox) bind(n int) string {
	if o.driver == config.Postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// failureLabel keeps only what an administrator can act on.
func failureLabel(err error) string {
	var delivery *DeliveryError
	switch {
	case errors.Is(err, ErrInvalidMessage):
		return "invalid_message"
	case errors.As(err, &delivery) && delivery.Code != "" && delivery.Status != 0:
		return fmt.Sprintf("http_%d:%s", delivery.Status, delivery.Code)
	case errors.As(err, &delivery) && delivery.Code != "":
		return delivery.Code
	case errors.As(err, &delivery) && delivery.Status != 0:
		return fmt.Sprintf("http_%d", delivery.Status)
	default:
		return "unreachable"
	}
}

func (o *Outbox) recordFailure(ctx context.Context, logger *slog.Logger, jobID, template, label string) {
	if len(label) > 200 {
		label = label[:200]
	}
	query := `INSERT INTO registry_email_failures (job_id, template, provider, error, failed_at_ms) VALUES (` + o.bind(1) + `, ` + o.bind(2) + `, ` + o.bind(3) + `, ` + o.bind(4) + `, ` + o.bind(5) + `) ON CONFLICT (job_id) DO NOTHING`
	if _, err := o.db.ExecContext(ctx, query, jobID, template, o.sender.Provider(), label, o.clock().UTC().UnixMilli()); err != nil {
		logger.Error("email failure could not be recorded", "job_id", jobID)
	}
}

const openFailures = `FROM registry_jobs j LEFT JOIN registry_email_failures f ON f.job_id = j.job_id WHERE j.kind = 'email.send' AND j.status = 'dead' AND f.resent_job_id IS NULL`

// Status counts waiting and failed messages.
func (o *Outbox) Status(ctx context.Context) (Status, error) {
	status := Status{Provider: o.sender.Provider()}
	var oldest sql.NullInt64
	if err := o.db.QueryRowContext(ctx, `SELECT COUNT(*), MIN(created_at_ms) FROM registry_jobs WHERE kind = 'email.send' AND status IN ('pending', 'running')`).Scan(&status.Pending, &oldest); err != nil {
		return Status{}, errors.New("email outbox status could not be read")
	}
	if oldest.Valid {
		status.OldestPending = time.UnixMilli(oldest.Int64).UTC()
	}
	if err := o.db.QueryRowContext(ctx, `SELECT COUNT(*) `+openFailures).Scan(&status.Failed); err != nil {
		return Status{}, errors.New("email outbox status could not be read")
	}
	return status, nil
}

// Failures lists the most recent failed deliveries that were not resent.
func (o *Outbox) Failures(ctx context.Context, limit int) ([]Failure, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	rows, err := o.db.QueryContext(ctx, `SELECT j.job_id, j.idempotency_key, j.payload, j.attempts, j.updated_at_ms, COALESCE(f.provider, ''), COALESCE(f.error, 'lease_expired') `+openFailures+` ORDER BY j.updated_at_ms DESC, j.job_id DESC LIMIT `+fmt.Sprint(limit))
	if err != nil {
		return nil, errors.New("email failures could not be listed")
	}
	defer rows.Close()
	var failures []Failure
	for rows.Next() {
		var job jobs.Job
		var updated int64
		var item Failure
		if err := rows.Scan(&job.ID, &job.Key, &job.Payload, &item.Attempts, &updated, &item.Provider, &item.Error); err != nil {
			return nil, errors.New("email failure could not be read")
		}
		item.JobID, item.FailedAt = job.ID, time.UnixMilli(updated).UTC()
		if message, err := o.open(job); err == nil {
			item.Template, item.Recipient = message.Template, maskAddress(message.To)
		} else {
			item.Template, item.Recipient = "unknown", "—"
		}
		failures = append(failures, item)
	}
	return failures, rows.Err()
}

// Resend queues a failed message again under a new idempotency key, so a
// provider that remembered the failed attempt sends it this time. The
// failure is marked as resent; if the new attempt fails too, it is listed
// on its own.
func (o *Outbox) Resend(ctx context.Context, actorUserID, jobID string) (string, error) {
	if _, err := uuid.Parse(jobID); err != nil {
		return "", ErrFailureUnknown
	}
	actor, err := uuid.Parse(actorUserID)
	if err != nil {
		return "", ErrFailureUnknown
	}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return "", errors.New("email resend could not start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := database.ReserveWrite(ctx, tx, o.driver); err != nil {
		return "", err
	}
	var job jobs.Job
	var resent sql.NullString
	var hasFailure bool
	err = tx.QueryRowContext(ctx, `SELECT j.job_id, j.idempotency_key, j.payload, f.resent_job_id, f.job_id IS NOT NULL FROM registry_jobs j LEFT JOIN registry_email_failures f ON f.job_id = j.job_id WHERE j.job_id = `+o.bind(1)+` AND j.kind = 'email.send' AND j.status = 'dead'`, jobID).Scan(&job.ID, &job.Key, &job.Payload, &resent, &hasFailure)
	if errors.Is(err, sql.ErrNoRows) || resent.Valid {
		return "", ErrFailureUnknown
	} else if err != nil {
		return "", errors.New("failed email could not be read")
	}
	message, err := o.open(job)
	if err != nil {
		return "", ErrFailureUnknown
	}
	base, _, _ := strings.Cut(job.Key, ":resend:")
	var previous int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_jobs WHERE kind = 'email.send' AND idempotency_key LIKE `+o.bind(1), base+":resend:%").Scan(&previous); err != nil {
		return "", errors.New("email resend could not be prepared")
	}
	key := fmt.Sprintf("%s:resend:%d", base, previous+1)
	if err := o.enqueueKeyTx(ctx, tx, key, message); err != nil {
		return "", err
	}
	var newID string
	if err := tx.QueryRowContext(ctx, `SELECT job_id FROM registry_jobs WHERE idempotency_key = `+o.bind(1), key).Scan(&newID); err != nil {
		return "", errors.New("resent email could not be read")
	}
	now := o.clock().UTC().UnixMilli()
	if hasFailure {
		_, err = tx.ExecContext(ctx, `UPDATE registry_email_failures SET resent_job_id = `+o.bind(1)+`, resent_by = `+o.bind(2)+`, resent_at_ms = `+o.bind(3)+` WHERE job_id = `+o.bind(4), newID, actor.String(), now, job.ID)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO registry_email_failures (job_id, template, provider, error, failed_at_ms, resent_job_id, resent_by, resent_at_ms) VALUES (`+o.bind(1)+`, `+o.bind(2)+`, `+o.bind(3)+`, 'lease_expired', `+o.bind(4)+`, `+o.bind(5)+`, `+o.bind(6)+`, `+o.bind(7)+`)`, job.ID, string(message.Template), o.sender.Provider(), now, newID, actor.String(), now)
	}
	if err != nil {
		return "", errors.New("email resend could not be recorded")
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return "", errors.New("email resend could not be audited")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, action, target_type, target_id, outcome, occurred_at) VALUES (`+o.bind(1)+`, `+o.bind(2)+`, 'user', 'email.resent', 'email', `+o.bind(3)+`, 'succeeded', `+o.bind(4)+`)`, eventID.String(), actor.String(), job.ID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return "", errors.New("email resend could not be audited")
	}
	if err := tx.Commit(); err != nil {
		return "", errors.New("email resend could not be saved")
	}
	return newID, nil
}

// maskAddress keeps the first character of the local part and the domain.
func maskAddress(address string) string {
	local, domain, found := strings.Cut(address, "@")
	if !found || local == "" {
		return "—"
	}
	return local[:1] + "…@" + domain
}
