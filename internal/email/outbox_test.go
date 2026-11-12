package email_test

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
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
	outbox, err := email.NewOutbox(queue, key, sender)
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
	outbox, err := email.NewOutbox(queue, key, &scriptedSender{})
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
