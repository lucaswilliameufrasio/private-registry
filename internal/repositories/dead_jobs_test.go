package repositories

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/jobs"
)

func TestSQLiteDeadJobAdministration(t *testing.T) {
	ctx, db, driver := openSQLite(t)
	service, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	admin := seedUser(t, ctx, db, driver, true)
	member := seedUser(t, ctx, db, driver, false)
	exerciseDeadJobAdministration(t, ctx, db, service, driver, admin, member)
}

func exerciseDeadJobAdministration(t *testing.T, ctx context.Context, db *sql.DB, service *Service, driver config.DatabaseDriver, admin, member string) {
	t.Helper()
	queue, err := jobs.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	id, err := queue.Enqueue(ctx, "test-dead-job", "expire-generic-uploads", `{"sensitive":"not-returned"}`, 1, now, now)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := queue.Claim(ctx, "expire-generic-uploads", now, time.Minute)
	if err != nil || claimed.ID != id {
		t.Fatalf("claim job = %+v, %v", claimed, err)
	}
	if err := queue.Finish(ctx, id, claimed.LeaseToken, false, now.Add(time.Second), now.Add(2*time.Second)); err != nil {
		t.Fatal("fail job:", err)
	}
	if _, _, err := service.ListDeadJobs(ctx, member, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin dead-job listing = %v", err)
	}
	if err := service.RetryDeadJob(ctx, member, id, 2); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin dead-job retry = %v", err)
	}
	dead, more, err := service.ListDeadJobs(ctx, admin, "", 10)
	if err != nil || more || len(dead) != 1 || dead[0].ID != id || dead[0].FailureCode != "operation_failed" || dead[0].Revision != 2 {
		t.Fatalf("dead jobs = %+v more=%t err=%v", dead, more, err)
	}
	oldRevision := dead[0].Revision
	otherID, err := queue.Enqueue(ctx, "other-dead-job", "private-internal-kind", `{"secret":"not-exposed"}`, 1, now, now)
	if err != nil {
		t.Fatal(err)
	}
	otherClaim, err := queue.Claim(ctx, "private-internal-kind", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Finish(ctx, otherID, otherClaim.LeaseToken, false, now.Add(time.Second), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	firstPage, more, err := service.ListDeadJobs(ctx, admin, "", 1)
	if err != nil || !more || len(firstPage) != 1 {
		t.Fatalf("first page = %+v more=%t err=%v", firstPage, more, err)
	}
	secondPage, more, err := service.ListDeadJobs(ctx, admin, firstPage[0].ID, 1)
	if err != nil || more || len(secondPage) != 1 || secondPage[0].ID == firstPage[0].ID {
		t.Fatalf("second page = %+v more=%t err=%v", secondPage, more, err)
	}
	for _, entry := range []DeadJob{firstPage[0], secondPage[0]} {
		if entry.ID == otherID && entry.Kind != "other" {
			t.Fatalf("unexpected exposed job kind: %q", entry.Kind)
		}
	}
	if err := service.RetryDeadJob(ctx, admin, otherID, 2); !errors.Is(err, ErrDeadJobConflict) {
		t.Fatalf("unapproved job kind could be retried: %v", err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- service.RetryDeadJob(ctx, admin, id, oldRevision) }()
	}
	var succeeded, conflicts int
	for range 2 {
		err := <-results
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrDeadJobConflict) {
			conflicts++
		} else {
			t.Fatalf("retry error = %v", err)
		}
	}
	if succeeded != 1 || conflicts != 1 {
		t.Fatalf("concurrent retry results: succeeded=%d conflicts=%d", succeeded, conflicts)
	}
	claimed, err = queue.Claim(ctx, "expire-generic-uploads", time.Now().UTC().Add(time.Second), time.Minute)
	if err != nil || claimed.ID != id || claimed.Attempts != 1 {
		t.Fatalf("retried job claim = %+v, %v", claimed, err)
	}
	if err := queue.Finish(ctx, id, claimed.LeaseToken, false, time.Now().UTC().Add(2*time.Second), time.Now().UTC().Add(3*time.Second)); err != nil {
		t.Fatal("fail retried job:", err)
	}
	if err := service.RetryDeadJob(ctx, admin, id, oldRevision); !errors.Is(err, ErrDeadJobConflict) {
		t.Fatalf("stale revision retried a second failure: %v", err)
	}
	var auditCount int
	query := `SELECT count(*) FROM registry_audit_events WHERE action = 'job.dead_letter.retried' AND actor_user_id = ` + bind(driver, 1)
	if err := db.QueryRowContext(ctx, query, admin).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("retry audit count=%d err=%v", auditCount, err)
	}
}
