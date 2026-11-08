package repositories

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"private-registry/internal/backup"
	"private-registry/internal/config"
	"private-registry/internal/jobs"
)

func TestSQLiteRecoveryJobAdministration(t *testing.T) {
	ctx, db, driver := openSQLite(t)
	service, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	admin := seedUser(t, ctx, db, driver, true)
	member := seedUser(t, ctx, db, driver, false)
	exerciseRecoveryJobAdministration(t, ctx, db, service, driver, admin, member)
}

func TestRecoveryJobReleaseRollsBackWhenAuditFails(t *testing.T) {
	ctx, db, driver := openSQLite(t)
	service, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	admin := seedUser(t, ctx, db, driver, true)
	queue, err := jobs.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	id, err := queue.Enqueue(ctx, "recovery-audit-failure", "expire-generic-uploads", "{}", 3, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_jobs SET recovery_previous_status = 'pending', revision = 1 WHERE job_id = ?`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_release_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'job.recovery.released' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := service.ReleaseRecoveryJob(ctx, admin, id, 1); err == nil {
		t.Fatal("release succeeded without audit")
	}
	var held string
	var revision int64
	if err := db.QueryRowContext(ctx, `SELECT recovery_previous_status, revision FROM registry_jobs WHERE job_id = ?`, id).Scan(&held, &revision); err != nil || held != "pending" || revision != 1 {
		t.Fatalf("failed release changed job: held=%q revision=%d err=%v", held, revision, err)
	}
	if _, err := queue.Claim(ctx, "expire-generic-uploads", now.Add(time.Minute), time.Minute); !errors.Is(err, jobs.ErrNoJob) {
		t.Fatalf("job claimable after failed release: %v", err)
	}
}

func exerciseRecoveryJobAdministration(t *testing.T, ctx context.Context, db *sql.DB, service *Service, driver config.DatabaseDriver, admin, member string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	queue, err := jobs.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	id, err := queue.Enqueue(ctx, "recovery-safe", "expire-generic-uploads", `{"secret":"not-exposed"}`, 3, now, now)
	if err != nil {
		t.Fatal(err)
	}
	active, err := queue.Claim(ctx, "expire-generic-uploads", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, err := queue.Enqueue(ctx, "recovery-other", "sensitive-internal-kind", `{"secret":"not-exposed"}`, 3, now, now)
	if err != nil {
		t.Fatal(err)
	}
	goID, err := queue.Enqueue(ctx, "recovery-go", "expire-go-uploads", `{"secret":"not-exposed"}`, 3, now, now)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	count, err := backup.HoldRestoredJobs(ctx, tx, driver, now)
	if err != nil || count != 3 {
		_ = tx.Rollback()
		t.Fatalf("hold jobs count=%d err=%v", count, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.ListRecoveryJobs(ctx, member, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member listed held jobs: %v", err)
	}
	items, more, err := service.ListRecoveryJobs(ctx, admin, "", 10)
	if err != nil || more || len(items) != 3 {
		t.Fatalf("held jobs = %+v more=%t err=%v", items, more, err)
	}
	firstPage, more, err := service.ListRecoveryJobs(ctx, admin, "", 1)
	if err != nil || !more || len(firstPage) != 1 {
		t.Fatalf("held jobs first page=%+v more=%t err=%v", firstPage, more, err)
	}
	secondPage, more, err := service.ListRecoveryJobs(ctx, admin, firstPage[0].ID, 1)
	if err != nil || !more || len(secondPage) != 1 || secondPage[0].ID == firstPage[0].ID {
		t.Fatalf("held jobs second page=%+v more=%t err=%v", secondPage, more, err)
	}
	thirdPage, more, err := service.ListRecoveryJobs(ctx, admin, secondPage[0].ID, 1)
	if err != nil || more || len(thirdPage) != 1 || thirdPage[0].ID == secondPage[0].ID {
		t.Fatalf("held jobs third page=%+v more=%t err=%v", thirdPage, more, err)
	}
	var revision, goRevision int64
	for _, item := range items {
		if item.ID == id {
			revision = item.Revision
			if item.PreviousStatus != "running" || item.Kind != "expire-generic-uploads" {
				t.Fatalf("safe held job = %+v", item)
			}
		}
		if item.ID == other && item.Kind != "other" {
			t.Fatalf("sensitive job kind exposed: %+v", item)
		}
		if item.ID == goID {
			goRevision = item.Revision
			if item.Kind != "expire-go-uploads" || item.PreviousStatus != "pending" {
				t.Fatalf("held Go expiration job = %+v", item)
			}
		}
	}
	if err := service.ReleaseRecoveryJob(ctx, member, id, revision); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member released held job: %v", err)
	}
	if err := service.ReleaseRecoveryJob(ctx, admin, other, 1); !errors.Is(err, ErrRecoveryJobConflict) {
		t.Fatalf("unapproved kind released: %v", err)
	}
	if err := service.ReleaseRecoveryJob(ctx, admin, id, revision-1); !errors.Is(err, ErrRecoveryJobConflict) {
		t.Fatalf("stale revision released: %v", err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- service.ReleaseRecoveryJob(ctx, admin, id, revision) }()
	}
	var succeeded, conflicts int
	for range 2 {
		err := <-results
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrRecoveryJobConflict) {
			conflicts++
		} else {
			t.Fatalf("recovery release error: %v", err)
		}
	}
	if succeeded != 1 || conflicts != 1 {
		t.Fatalf("concurrent recovery release success=%d conflict=%d", succeeded, conflicts)
	}
	if err := service.ReleaseRecoveryJob(ctx, admin, id, revision); !errors.Is(err, ErrRecoveryJobConflict) {
		t.Fatalf("held job released twice: %v", err)
	}
	if err := service.ReleaseRecoveryJob(ctx, member, goID, goRevision); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member released held Go job: %v", err)
	}
	if err := service.ReleaseRecoveryJob(ctx, admin, goID, goRevision); err != nil {
		t.Fatalf("administrator could not release Go expiration: %v", err)
	}
	if err := service.ReleaseRecoveryJob(ctx, admin, goID, goRevision); !errors.Is(err, ErrRecoveryJobConflict) {
		t.Fatalf("held Go job released twice: %v", err)
	}
	if err := queue.Finish(ctx, id, active.LeaseToken, true, now.Add(time.Second), time.Time{}); !errors.Is(err, jobs.ErrLease) {
		t.Fatalf("old lease remained valid: %v", err)
	}
	reclaimed, err := queue.Claim(ctx, "expire-generic-uploads", time.Now().UTC().Add(time.Second), time.Minute)
	if err != nil || reclaimed.ID != id || reclaimed.LeaseToken == active.LeaseToken {
		t.Fatalf("released job claim=%+v err=%v", reclaimed, err)
	}
	var audit int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_audit_events WHERE action = 'job.recovery.released' AND actor_user_id = `+bind(driver, 1), admin).Scan(&audit); err != nil || audit != 2 {
		t.Fatalf("recovery release audit=%d err=%v", audit, err)
	}
}
