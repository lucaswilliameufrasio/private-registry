//go:build integration && linux

package authattempts

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

func TestPostgresConcurrentAttemptsRespectAccountLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	postgres, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := postgres.Stop(); err != nil {
			t.Errorf("stop owned PostgreSQL fixture: %v", err)
		}
	})
	cfg := config.Config{
		DatabaseDriver:       config.Postgres,
		DatabaseDSN:          postgres.DSN(),
		DatabaseMaxOpenConns: 16,
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
	limiter, err := New(db, config.Postgres)
	if err != nil {
		t.Fatal(err)
	}

	const callers = 12
	start := make(chan struct{})
	results := make(chan error, callers)
	var waitGroup sync.WaitGroup
	for index := 0; index < callers; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			_, err := limiter.BeginPassword(ctx, "parallel.user", "192.0.2.100")
			results <- err
		}(index)
	}
	close(start)
	waitGroup.Wait()
	close(results)

	admitted := 0
	limited := 0
	for err := range results {
		if err == nil {
			admitted++
			continue
		}
		if errors.Is(err, ErrRateLimited) {
			limited++
			continue
		}
		t.Fatalf("PostgreSQL concurrent attempt returned unexpected error: %v", err)
	}
	if admitted != accountLimit || limited != callers-accountLimit {
		t.Fatalf("got %d admitted and %d limited attempts, want %d and %d",
			admitted, limited, accountLimit, callers-accountLimit)
	}
	var storedCount int
	if err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM registry_auth_attempt_buckets WHERE octet_length(attempt_times) = $1",
		accountLimit*8).Scan(&storedCount); err != nil {
		t.Fatal(err)
	}
	if storedCount != 1 {
		t.Fatalf("PostgreSQL persisted %d account buckets at the attempt limit, want one", storedCount)
	}
}
