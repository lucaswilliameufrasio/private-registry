// Package maintenance runs bounded, recoverable maintenance tasks.
package maintenance

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"private-registry/internal/artifacts"
	"private-registry/internal/cargo"
	"private-registry/internal/gomod"
	"private-registry/internal/jobs"
)

const (
	expirationKey       = "maintenance:expire-generic-uploads:v1"
	expirationKind      = "expire-generic-uploads"
	goExpirationKey     = "maintenance:expire-go-uploads:v1"
	goExpirationKind    = "expire-go-uploads"
	cargoExpirationKey  = "maintenance:expire-cargo-reservations:v1"
	cargoExpirationKind = "expire-cargo-reservations"
	batchSize           = 128
	runInterval         = time.Minute
	operationLimit      = 10 * time.Second
	leaseDuration       = 30 * time.Second
)

type UploadExpiration struct {
	queue     *jobs.Queue
	artifacts uploadExpirer
	clock     func() time.Time
	key       string
	kind      string
}

func NewCargoReservationExpiration(queue *jobs.Queue, service *cargo.ReservationService) (*UploadExpiration, error) {
	if queue == nil || service == nil {
		return nil, errors.New("Cargo reservation expiration dependencies are required")
	}
	return &UploadExpiration{queue: queue, artifacts: service, clock: time.Now, key: cargoExpirationKey, kind: cargoExpirationKind}, nil
}

type uploadExpirer interface {
	ExpireUploadBatch(context.Context, time.Time, int) (int, error)
}

func NewUploadExpiration(queue *jobs.Queue, service *artifacts.Service) (*UploadExpiration, error) {
	if queue == nil || service == nil {
		return nil, errors.New("upload expiration dependencies are required")
	}
	return &UploadExpiration{queue: queue, artifacts: service, clock: time.Now, key: expirationKey, kind: expirationKind}, nil
}

func NewGoUploadExpiration(queue *jobs.Queue, service *gomod.Service) (*UploadExpiration, error) {
	if queue == nil || service == nil {
		return nil, errors.New("Go upload expiration dependencies are required")
	}
	return &UploadExpiration{queue: queue, artifacts: service, clock: time.Now, key: goExpirationKey, kind: goExpirationKind}, nil
}

// RunOnce schedules and executes at most one bounded batch. A persistent job
// retains retries across restarts; repeated expiration is safe, but object GC
// and cleanup of private staging files remain separate work.
func (w *UploadExpiration) RunOnce(ctx context.Context) error {
	if w == nil || w.queue == nil || w.artifacts == nil || ctx == nil {
		return errors.New("upload expiration worker is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, operationLimit)
	defer cancel()
	now := w.clock().UTC()
	id, err := w.queue.Enqueue(ctx, w.key, w.kind, "{}", 8, time.Unix(1, 0).UTC(), now)
	if err != nil {
		return err
	}
	job, err := w.queue.Claim(ctx, w.kind, now, leaseDuration)
	if errors.Is(err, jobs.ErrNoJob) {
		status, statusErr := w.queue.Status(ctx, id)
		if statusErr != nil {
			return statusErr
		}
		if status == "dead" {
			return errors.New("upload expiration job exhausted its attempts and requires operator review")
		}
		return nil
	}
	if err != nil {
		return err
	}
	if job.ID != id {
		return errors.New("unexpected upload expiration job identity")
	}
	_, err = w.artifacts.ExpireUploadBatch(ctx, now, batchSize)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		finishTime := w.clock().UTC()
		backoff := time.Duration(1<<min(job.Attempts-1, 6)) * 5 * time.Second
		backoff += time.Duration(rand.Int64N(int64(time.Second)))
		if finishErr := w.queue.Finish(ctx, job.ID, job.LeaseToken, false, finishTime, finishTime.Add(backoff)); finishErr != nil {
			return errors.Join(err, finishErr)
		}
		return err
	}
	finishTime := w.clock().UTC()
	return w.queue.Reschedule(ctx, job.ID, job.LeaseToken, finishTime, finishTime.Add(runInterval))
}

// Run stops scheduling as soon as ctx is canceled. Each in-flight database
// operation has its own deadline; an interrupted claim is recovered by lease.
func (w *UploadExpiration) Run(ctx context.Context, logger *slog.Logger) {
	if w == nil || ctx == nil || logger == nil {
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		delay := 10 * time.Second
		if err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
			logger.Error("upload expiration maintenance failed", "kind", w.kind, "error", err)
			delay = time.Minute
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
