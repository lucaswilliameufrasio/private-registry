package jobs

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
)

func TestSQLiteQueueClaimsAndFencing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "data")
	cfg := config.Config{DataDir: root, DatabaseDriver: config.SQLite, DatabaseDSN: filepath.Join(root, "registry.sqlite"), DatabaseMaxOpenConns: 4}
	ctx := context.Background()
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	exerciseQueue(t, db, cfg.DatabaseDriver)
}

func exerciseQueue(t *testing.T, db *sql.DB, driver config.DatabaseDriver) {
	t.Helper()
	ctx := context.Background()
	q, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	id, err := q.Enqueue(ctx, "synthetic-key", "expire-upload", "{}", 3, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if repeated, err := q.Enqueue(ctx, "synthetic-key", "expire-upload", "{}", 3, now, now); err != nil || repeated != id {
		t.Fatalf("idempotent enqueue = %q, %v", repeated, err)
	}
	if _, err := q.Enqueue(ctx, "synthetic-key", "expire-upload", "different", 3, now, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting enqueue = %v", err)
	}
	results := make(chan struct {
		job Job
		err error
	}, 2)
	for range 2 {
		go func() {
			job, err := q.Claim(ctx, "expire-upload", now, time.Minute)
			results <- struct {
				job Job
				err error
			}{job, err}
		}()
	}
	var first Job
	var successes, empty int
	for range 2 {
		result := <-results
		if result.err == nil {
			first = result.job
			successes++
		} else if errors.Is(result.err, ErrNoJob) {
			empty++
		} else {
			t.Fatalf("claim failed: %v", result.err)
		}
	}
	if successes != 1 || empty != 1 || first.ID != id || first.Attempts != 1 {
		t.Fatalf("claims: successes=%d empty=%d job=%+v", successes, empty, first)
	}
	if err := q.Heartbeat(ctx, id, first.LeaseToken, now.Add(30*time.Second), time.Minute); err != nil {
		t.Fatal("heartbeat:", err)
	}
	if _, err := q.Claim(ctx, "expire-upload", now.Add(70*time.Second), time.Minute); !errors.Is(err, ErrNoJob) {
		t.Fatalf("extended lease was reclaimed: %v", err)
	}
	second, err := q.Claim(ctx, "expire-upload", now.Add(91*time.Second), time.Minute)
	if err != nil || second.Attempts != 2 || second.LeaseToken == first.LeaseToken {
		t.Fatalf("reclaim = %+v, %v", second, err)
	}
	if err := q.Finish(ctx, id, first.LeaseToken, true, now.Add(92*time.Second), time.Time{}); !errors.Is(err, ErrLease) {
		t.Fatalf("stale worker finish = %v", err)
	}
	if err := q.Finish(ctx, id, second.LeaseToken, false, now.Add(92*time.Second), now.Add(2*time.Minute)); err != nil {
		t.Fatal("schedule retry:", err)
	}
	if _, err := q.Claim(ctx, "expire-upload", now.Add(119*time.Second), time.Minute); !errors.Is(err, ErrNoJob) {
		t.Fatalf("retry claimed before its scheduled time: %v", err)
	}
	if repeated, err := q.Enqueue(ctx, "synthetic-key", "expire-upload", "{}", 3, now, now); err != nil || repeated != id {
		t.Fatalf("enqueue after retry = %q, %v", repeated, err)
	}
	third, err := q.Claim(ctx, "expire-upload", now.Add(2*time.Minute), time.Minute)
	if err != nil || third.Attempts != 3 {
		t.Fatalf("retry claim = %+v, %v", third, err)
	}
	if err := q.Finish(ctx, id, third.LeaseToken, false, now.Add(121*time.Second), now.Add(3*time.Minute)); err != nil {
		t.Fatal("dead-letter exhausted job:", err)
	}
	if _, err := q.Claim(ctx, "expire-upload", now.Add(4*time.Minute), time.Minute); !errors.Is(err, ErrNoJob) {
		t.Fatalf("dead job was claimed: %v", err)
	}
	completedID, err := q.Enqueue(ctx, "successful-key", "expire-upload", "{}", 1, now, now)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := q.Claim(ctx, "expire-upload", now, time.Minute)
	if err != nil || completed.ID != completedID {
		t.Fatalf("success claim = %+v, %v", completed, err)
	}
	if err := q.Finish(ctx, completedID, completed.LeaseToken, true, now.Add(time.Second), time.Time{}); err != nil {
		t.Fatal("complete job:", err)
	}
	if err := q.Heartbeat(ctx, completedID, completed.LeaseToken, now.Add(2*time.Second), time.Minute); !errors.Is(err, ErrLease) {
		t.Fatalf("completed job heartbeat = %v", err)
	}
	if _, err := q.Claim(ctx, "expire-upload", now.Add(4*time.Minute), time.Minute); !errors.Is(err, ErrNoJob) {
		t.Fatalf("completed job was claimed: %v", err)
	}
	recurringID, err := q.Enqueue(ctx, "recurring-key", "expire-upload", "{}", 2, now, now)
	if err != nil {
		t.Fatal(err)
	}
	run, err := q.Claim(ctx, "expire-upload", now, time.Minute)
	if err != nil || run.ID != recurringID {
		t.Fatalf("recurring claim = %+v, %v", run, err)
	}
	if err := q.Reschedule(ctx, recurringID, run.LeaseToken, now.Add(time.Second), now.Add(2*time.Minute)); err != nil {
		t.Fatal("reschedule recurring job:", err)
	}
	if err := q.Reschedule(ctx, recurringID, run.LeaseToken, now.Add(2*time.Second), now.Add(3*time.Minute)); !errors.Is(err, ErrLease) {
		t.Fatalf("stale reschedule = %v", err)
	}
	if _, err := q.Claim(ctx, "expire-upload", now.Add(119*time.Second), time.Minute); !errors.Is(err, ErrNoJob) {
		t.Fatalf("recurring job ran early: %v", err)
	}
	secondRun, err := q.Claim(ctx, "expire-upload", now.Add(2*time.Minute), time.Minute)
	if err != nil || secondRun.ID != recurringID || secondRun.Attempts != 1 || secondRun.LeaseToken == run.LeaseToken {
		t.Fatalf("recurring second run = %+v, %v", secondRun, err)
	}
}
