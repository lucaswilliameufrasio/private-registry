//go:build integration

package sessions

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/testinfra"
)

func TestPostgresSessionsRotateValidateAndRevokeConcurrently(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	fixture, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Errorf("stop owned PostgreSQL fixture: %v", err)
		}
	})
	cfg := config.Config{
		DatabaseDriver:       config.Postgres,
		DatabaseDSN:          fixture.DSN(),
		DatabaseMaxOpenConns: 8,
	}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test PostgreSQL database: %v", err)
		}
	})
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	userID, err := insertTestUser(ctx, db, config.Postgres, "session.postgres")
	if err != nil {
		t.Fatal(err)
	}
	store, err := New(db, config.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time {
		return now
	}

	initial, err := store.Create(ctx, userID, LevelEnrollmentOnly)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertActiveFactor(ctx, db, config.Postgres, userID); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	rotated, err := store.Rotate(ctx, initial.BearerToken, LevelMFA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Validate(ctx, initial.BearerToken); !errors.Is(err, ErrSessionUnavailable) {
		t.Fatalf("PostgreSQL accepted a rotated bearer: %v", err)
	}

	const callers = 6
	start := make(chan struct{})
	results := make(chan error, callers)
	var waitGroup sync.WaitGroup
	for range callers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := store.ValidateWithCSRF(ctx, rotated.BearerToken, rotated.CSRFToken)
			results <- err
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent PostgreSQL session validation failed: %v", err)
		}
	}

	if err := store.RevokeUserSessions(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Validate(ctx, rotated.BearerToken); !errors.Is(err, ErrSessionUnavailable) {
		t.Fatalf("PostgreSQL accepted a user-revoked bearer: %v", err)
	}
}
