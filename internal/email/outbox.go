package email

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/jobs"
	"private-registry/internal/secrets"
)

const (
	jobKind       = "email.send"
	maxAttempts   = 10
	leaseDuration = 2 * time.Minute
	idleDelay     = 5 * time.Second
)

// Enqueuer is what the services that send mail depend on: it records a
// message inside their transaction, so it exists exactly when their change
// commits.
type Enqueuer interface {
	EnqueueTx(ctx context.Context, tx *sql.Tx, key string, message Message) error
}

// Outbox stores messages as jobs. Payloads are sealed with the master key:
// they hold recipients and single-use links, and the database (and its
// backups) must not reveal them.
type Outbox struct {
	db     *sql.DB
	driver config.DatabaseDriver
	queue  *jobs.Queue
	key    *secrets.MasterKey
	sender Sender
	clock  func() time.Time
}

func NewOutbox(db *sql.DB, driver config.DatabaseDriver, queue *jobs.Queue, key *secrets.MasterKey, sender Sender) (*Outbox, error) {
	if db == nil || (driver != config.SQLite && driver != config.Postgres) || queue == nil || key == nil || sender == nil {
		return nil, errors.New("email outbox is misconfigured")
	}
	return &Outbox{db: db, driver: driver, queue: queue, key: key, sender: sender, clock: time.Now}, nil
}

func (o *Outbox) Provider() string { return o.sender.Provider() }

func sealContext(key string) []byte { return []byte("private-registry/email/v1\x00" + key) }

// EnqueueTx validates and seals message under key. The key names the
// business event (for example "recovery:<reset id>") and becomes the
// provider idempotency key, so a message is never delivered twice.
func (o *Outbox) EnqueueTx(ctx context.Context, tx *sql.Tx, key string, message Message) error {
	if o == nil || ctx == nil || tx == nil {
		return errors.New("email outbox is unavailable")
	}
	if err := message.Validate(); err != nil {
		return err
	}
	return o.enqueueKeyTx(ctx, tx, "email:"+key, message)
}

func (o *Outbox) enqueueKeyTx(ctx context.Context, tx *sql.Tx, key string, message Message) error {
	if !validKey(key) {
		return ErrInvalidMessage
	}
	plaintext, err := json.Marshal(message)
	if err != nil {
		return ErrInvalidMessage
	}
	defer clear(plaintext)
	sealed, err := o.key.Seal(plaintext, sealContext(key))
	if err != nil {
		return errors.New("email could not be sealed")
	}
	now := o.clock().UTC()
	if _, err := o.queue.EnqueueTx(ctx, tx, key, jobKind, base64.RawStdEncoding.EncodeToString(sealed), maxAttempts, now, now); err != nil {
		return errors.New("email could not be queued")
	}
	return nil
}

// DeliverOnce sends at most one due message. It reports whether a message
// was claimed.
func (o *Outbox) DeliverOnce(ctx context.Context, logger *slog.Logger) (bool, error) {
	now := o.clock().UTC()
	job, err := o.queue.Claim(ctx, jobKind, now, leaseDuration)
	if errors.Is(err, jobs.ErrNoJob) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	message, err := o.open(job)
	if err != nil {
		logger.Error("queued email could not be opened and was abandoned", "job_id", job.ID)
		if err := o.queue.Abandon(ctx, job.ID, job.LeaseToken, o.clock().UTC()); err != nil {
			return true, err
		}
		o.recordFailure(ctx, logger, job.ID, "unknown", "payload_unreadable")
		return true, nil
	}
	sendErr := o.sender.Send(ctx, message, job.Key)
	finished := o.clock().UTC()
	switch {
	case sendErr == nil:
		logger.Info("email delivered to provider", "provider", o.sender.Provider(), "template", message.Template, "job_id", job.ID, "attempt", job.Attempts)
		return true, o.queue.Finish(ctx, job.ID, job.LeaseToken, true, finished, time.Time{})
	case IsPermanent(sendErr):
		logger.Error("email rejected by provider and abandoned", "provider", o.sender.Provider(), "template", message.Template, "job_id", job.ID, "error", sendErr)
		if err := o.queue.Abandon(ctx, job.ID, job.LeaseToken, finished); err != nil {
			return true, err
		}
		o.recordFailure(ctx, logger, job.ID, string(message.Template), failureLabel(sendErr))
		return true, nil
	case job.Attempts >= job.MaxAttempts:
		logger.Error("email delivery failed on its last attempt and was abandoned", "provider", o.sender.Provider(), "template", message.Template, "job_id", job.ID, "attempt", job.Attempts, "error", sendErr)
		if err := o.queue.Finish(ctx, job.ID, job.LeaseToken, false, finished, finished); err != nil {
			return true, err
		}
		o.recordFailure(ctx, logger, job.ID, string(message.Template), failureLabel(sendErr))
		return true, nil
	default:
		delay := backoff(job.Attempts)
		if wait := retryAfter(sendErr); wait > delay {
			delay = wait
		}
		logger.Warn("email delivery failed and will be retried", "provider", o.sender.Provider(), "template", message.Template, "job_id", job.ID, "attempt", job.Attempts, "max_attempts", job.MaxAttempts, "retry_in", delay.String(), "error", sendErr)
		return true, o.queue.Finish(ctx, job.ID, job.LeaseToken, false, finished, finished.Add(delay))
	}
}

func (o *Outbox) open(job jobs.Job) (Message, error) {
	sealed, err := base64.RawStdEncoding.DecodeString(job.Payload)
	if err != nil {
		return Message{}, err
	}
	plaintext, err := o.key.Open(sealed, sealContext(job.Key))
	if err != nil {
		return Message{}, err
	}
	defer clear(plaintext)
	var message Message
	if err := json.Unmarshal(plaintext, &message); err != nil {
		return Message{}, err
	}
	return message, message.Validate()
}

// backoff grows from 30 seconds to an hour, with jitter so retries after a
// provider outage do not arrive together.
func backoff(attempt int) time.Duration {
	delay := 30 * time.Second << min(max(attempt-1, 0), 7)
	delay = min(delay, time.Hour)
	return delay + time.Duration(rand.Int64N(int64(delay/5)+1))
}

// Run delivers until ctx is canceled. An interrupted send is reclaimed after
// its lease and retried with the same idempotency key.
func (o *Outbox) Run(ctx context.Context, logger *slog.Logger) {
	if o == nil || ctx == nil || logger == nil {
		return
	}
	for ctx.Err() == nil {
		claimed, err := o.DeliverOnce(ctx, logger)
		if err != nil && ctx.Err() == nil {
			logger.Error("email outbox failed", "error", err)
		}
		if claimed && err == nil {
			continue
		}
		timer := time.NewTimer(idleDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
