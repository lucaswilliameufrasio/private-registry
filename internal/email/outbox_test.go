package email_test

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/email"
	"private-registry/internal/jobs"
	"private-registry/internal/migrations"
	"private-registry/internal/secrets"
)

type scriptedSender struct {
	mu      sync.Mutex
	results []error
	keys    []string
	sent    []email.Message
}

func (s *scriptedSender) Provider() string { return "scripted" }

func (s *scriptedSender) Send(_ context.Context, message email.Message, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, key)
	s.sent = append(s.sent, message)
	if len(s.results) == 0 {
		return nil
	}
	result := s.results[0]
	s.results = s.results[1:]
	return result
}

func openOutboxFixture(t *testing.T) (*sql.DB, *jobs.Queue, *secrets.MasterKey) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	keyDir := filepath.Join(root, "keys")
	for _, dir := range []string{dataDir, keyDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Config{DataDir: dataDir, DatabaseDriver: config.SQLite, DatabaseDSN: filepath.Join(dataDir, "registry.sqlite"), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "master.key")
	if err := secrets.InitializeMasterKey(keyPath, dataDir); err != nil {
		t.Fatal(err)
	}
	key, err := secrets.LoadMasterKeyFile(keyPath, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	queue, err := jobs.New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	return db, queue, &key
}

func message(to string) email.Message {
	return email.Message{Template: email.TemplateSecurityNotice, To: to, Data: map[string]string{"display_name": "Ana", "event_label": "nova passkey cadastrada", "occurred_at": "2026-11-12 12:00", "registry_url": "https://registry.example"}}
}

func enqueue(t *testing.T, db *sql.DB, outbox *email.Outbox, key string, m email.Message) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.EnqueueTx(context.Background(), tx, key, m); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestOutboxSealsRetriesAndAbandons(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, queue, key := openOutboxFixture(t)
	sender := &scriptedSender{results: []error{&email.DeliveryError{Provider: "scripted", Status: 503}, nil, &email.DeliveryError{Provider: "scripted", Status: 422, Permanent: true}}}
	outbox, err := email.NewOutbox(db, config.SQLite, queue, key, sender)
	if err != nil {
		t.Fatal(err)
	}
	enqueue(t, db, outbox, "notice:1", message("ana@example.com"))

	// Recipients and links are sealed at rest.
	var payload string
	if err := db.QueryRowContext(ctx, `SELECT payload FROM registry_jobs WHERE idempotency_key = 'email:notice:1'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, "ana@") || strings.Contains(payload, "registry.example") {
		t.Fatal("email payload is stored in plaintext")
	}

	if claimed, err := outbox.DeliverOnce(ctx, logger); !claimed || err != nil {
		t.Fatalf("first attempt: %v %v", claimed, err)
	}
	// The retry is scheduled in the future; make it due.
	if _, err := db.ExecContext(ctx, `UPDATE registry_jobs SET available_at_ms = 0 WHERE idempotency_key = 'email:notice:1'`); err != nil {
		t.Fatal(err)
	}
	if claimed, err := outbox.DeliverOnce(ctx, logger); !claimed || err != nil {
		t.Fatalf("retry: %v %v", claimed, err)
	}
	if len(sender.keys) != 2 || sender.keys[0] != sender.keys[1] || sender.keys[0] != "email:notice:1" || sender.sent[1].To != "ana@example.com" {
		t.Fatalf("retry must reuse the idempotency key: %v", sender.keys)
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM registry_jobs WHERE idempotency_key = 'email:notice:1'`).Scan(&status); err != nil || status != "succeeded" {
		t.Fatalf("status %q %v", status, err)
	}

	enqueue(t, db, outbox, "notice:2", message("bia@example.com"))
	if claimed, err := outbox.DeliverOnce(ctx, logger); !claimed || err != nil {
		t.Fatalf("permanent: %v %v", claimed, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT status FROM registry_jobs WHERE idempotency_key = 'email:notice:2'`).Scan(&status); err != nil || status != "dead" {
		t.Fatalf("permanent failure must not be retried: %q %v", status, err)
	}
	if claimed, err := outbox.DeliverOnce(ctx, logger); claimed || err != nil {
		t.Fatalf("queue should be empty: %v %v", claimed, err)
	}

	// Invalid messages never enter the queue.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := outbox.EnqueueTx(ctx, tx, "notice:3", message("not-an-address")); !errors.Is(err, email.ErrInvalidMessage) {
		t.Fatalf("invalid message queued: %v", err)
	}
}

func TestOutboxRollsBackWithTheTransaction(t *testing.T) {
	ctx := context.Background()
	db, queue, key := openOutboxFixture(t)
	outbox, err := email.NewOutbox(db, config.SQLite, queue, key, &scriptedSender{})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.EnqueueTx(ctx, tx, "notice:rolled-back", message("ana@example.com")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_jobs WHERE kind = 'email.send'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled back email was queued: %d %v", count, err)
	}
}

func TestFailuresAreRecordedListedAndResent(t *testing.T) {
	db, queue, key := openOutboxFixture(t)
	ExerciseFailuresAndResend(t, db, config.SQLite, queue, key)
}

// ExerciseFailuresAndResend is shared with the PostgreSQL test.
func ExerciseFailuresAndResend(t *testing.T, db *sql.DB, driver config.DatabaseDriver, queue *jobs.Queue, key *secrets.MasterKey) {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	q := func(query string) string {
		if driver != config.Postgres {
			return query
		}
		for n := 1; strings.Contains(query, "?"); n++ {
			query = strings.Replace(query, "?", "$"+strconv.Itoa(n), 1)
		}
		return query
	}
	admin := "0190a0a0-0000-7000-8000-000000000001"
	if _, err := db.ExecContext(ctx, q(`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (?, 'Admin', 'now', 'now')`), admin); err != nil {
		t.Fatal(err)
	}
	sender := &scriptedSender{results: []error{&email.DeliveryError{Provider: "scripted", Status: 404, Code: "TEMPLATE_NOT_FOUND", Permanent: true}}}
	outbox, err := email.NewOutbox(db, driver, queue, key, sender)
	if err != nil {
		t.Fatal(err)
	}
	enqueue(t, db, outbox, "notice:failing", message("ana@example.com"))
	if _, err := outbox.DeliverOnce(ctx, logger); err != nil {
		t.Fatal(err)
	}
	status, err := outbox.Status(ctx)
	if err != nil || status.Failed != 1 || status.Pending != 0 || status.Provider != "scripted" {
		t.Fatalf("status: %+v %v", status, err)
	}
	failures, err := outbox.Failures(ctx, 10)
	if err != nil || len(failures) != 1 {
		t.Fatalf("failures: %+v %v", failures, err)
	}
	failed := failures[0]
	if failed.Template != email.TemplateSecurityNotice || failed.Error != "http_404:TEMPLATE_NOT_FOUND" || failed.Recipient != "a…@example.com" || failed.Provider != "scripted" {
		t.Fatalf("failure: %+v", failed)
	}

	resent, err := outbox.Resend(ctx, admin, failed.JobID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outbox.Resend(ctx, admin, failed.JobID); !errors.Is(err, email.ErrFailureUnknown) {
		t.Fatalf("resent twice: %v", err)
	}
	status, _ = outbox.Status(ctx)
	if status.Failed != 0 || status.Pending != 1 {
		t.Fatalf("after resend: %+v", status)
	}
	if _, err := outbox.DeliverOnce(ctx, logger); err != nil {
		t.Fatal(err)
	}
	if got := sender.keys[len(sender.keys)-1]; got != "email:notice:failing:resend:1" || sender.sent[len(sender.sent)-1].To != "ana@example.com" {
		t.Fatalf("resend must use a new key and the same message: %q", got)
	}
	var state string
	if err := db.QueryRowContext(ctx, q(`SELECT status FROM registry_jobs WHERE job_id = ?`), resent).Scan(&state); err != nil || state != "succeeded" {
		t.Fatalf("resent job: %q %v", state, err)
	}
	var audits int
	if err := db.QueryRowContext(ctx, q(`SELECT COUNT(*) FROM registry_audit_events WHERE action = 'email.resent' AND actor_user_id = ?`), admin).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("resend audit: %d %v", audits, err)
	}

	// Exhausting the attempts on temporary errors also counts as a failure.
	exhaust := make([]error, 10)
	for i := range exhaust {
		exhaust[i] = &email.DeliveryError{Provider: "scripted", Status: 503}
	}
	sender.results = exhaust
	enqueue(t, db, outbox, "notice:exhausted", message("bia@example.com"))
	for i := 0; i < 10; i++ {
		if _, err := db.ExecContext(ctx, `UPDATE registry_jobs SET available_at_ms = 0 WHERE idempotency_key = 'email:notice:exhausted' AND status = 'pending'`); err != nil {
			t.Fatal(err)
		}
		if _, err := outbox.DeliverOnce(ctx, logger); err != nil {
			t.Fatal(err)
		}
	}
	failures, _ = outbox.Failures(ctx, 10)
	if len(failures) != 1 || failures[0].Error != "http_503" || failures[0].Attempts != 10 {
		t.Fatalf("exhausted failure: %+v", failures)
	}
}
