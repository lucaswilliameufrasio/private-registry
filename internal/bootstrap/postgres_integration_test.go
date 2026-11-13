//go:build integration

package bootstrap

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/testinfra"
)

func TestCreateFirstAdminSerializesConcurrentPostgresBootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
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
		DataDir:              filepath.Join(t.TempDir(), "registry-data"),
		DatabaseDriver:       config.Postgres,
		DatabaseDSN:          fixture.DSN(),
		DatabaseMaxOpenConns: 4,
	}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close PostgreSQL database: %v", err)
		}
	})
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}

	type result struct {
		userID string
		err    error
	}
	inputs := []AdminInput{
		validAdminInput([]byte("first valid password with length 1")),
		{
			LoginName:     "second.admin",
			DisplayName:   "Second Operator",
			Email:         "second.admin@example.test",
			Password:      []byte("second valid password with length 2"),
			OperatorLabel: "another-host-user",
		},
	}
	start := make(chan struct{})
	results := make(chan result, len(inputs))
	var waitGroup sync.WaitGroup
	for _, input := range inputs {
		waitGroup.Add(1)
		go func(input AdminInput) {
			defer waitGroup.Done()
			<-start
			userID, err := CreateFirstAdmin(ctx, db, config.Postgres, input)
			clear(input.Password)
			results <- result{userID: userID, err: err}
		}(input)
	}
	close(start)
	waitGroup.Wait()
	close(results)

	successes := 0
	alreadyBootstrapped := 0
	for result := range results {
		if result.err == nil {
			successes++
			if result.userID == "" {
				t.Error("successful PostgreSQL bootstrap returned an empty user identity")
			}
			continue
		}
		if errors.Is(result.err, ErrAlreadyBootstrapped) {
			alreadyBootstrapped++
			continue
		}
		t.Errorf("unexpected concurrent PostgreSQL bootstrap result: %v", result.err)
	}
	if successes != 1 || alreadyBootstrapped != 1 {
		t.Fatalf("bootstrap did not serialize to one winner: successes=%d already=%d", successes, alreadyBootstrapped)
	}

	for _, table := range []string{"registry_users", "registry_local_credentials", "registry_instance_admins", "registry_audit_events"} {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("concurrent bootstrap left %d records in %s, want exactly one", count, table)
		}
	}
}
