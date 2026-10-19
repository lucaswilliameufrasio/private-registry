//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/testinfra"
)

func TestMigratePostgresRealDatabaseAndAdvisoryLock(t *testing.T) {
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
		DatabaseMaxOpenConns: 4,
	}
	firstDB, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := firstDB.Close(); err != nil {
			t.Errorf("close first PostgreSQL connection: %v", err)
		}
	})
	secondDB, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := secondDB.Close(); err != nil {
			t.Errorf("close second PostgreSQL connection: %v", err)
		}
	})

	type migrationResult struct {
		report Report
		err    error
	}
	start := make(chan struct{})
	results := make(chan migrationResult, 2)
	for _, db := range []*sql.DB{firstDB, secondDB} {
		go func(db *sql.DB) {
			<-start
			report, err := Migrate(ctx, db, cfg)
			results <- migrationResult{report: report, err: err}
		}(db)
	}
	close(start)
	var first Report
	var installationID string
	appliedCount := 0
	var migrationErrors []error
	for range 2 {
		result := <-results
		if result.err != nil {
			migrationErrors = append(migrationErrors, result.err)
			continue
		}
		if result.report.CurrentVersion != 6 || result.report.TargetVersion != 6 || result.report.InstallationID == "" {
			migrationErrors = append(migrationErrors, errors.New("unexpected concurrent PostgreSQL migration report"))
			continue
		}
		if installationID == "" {
			installationID = result.report.InstallationID
		} else if result.report.InstallationID != installationID {
			migrationErrors = append(migrationErrors, errors.New("concurrent migrations created different installation identities"))
		}
		if len(result.report.AppliedVersions) == 6 {
			first = result.report
			appliedCount++
		} else if len(result.report.AppliedVersions) != 0 {
			migrationErrors = append(migrationErrors, errors.New("concurrent migration applied an unexpected version count"))
		}
	}
	if err := errors.Join(migrationErrors...); err != nil {
		t.Fatal(err)
	}
	if appliedCount != 1 || first.CurrentVersion != 6 || first.TargetVersion != 6 || first.InstallationID == "" {
		t.Fatalf("PostgreSQL advisory lock did not serialize migration callers: first=%+v applied=%d", first, appliedCount)
	}

	var attempts int
	if err := firstDB.QueryRowContext(ctx,
		"SELECT count(*) FROM registry_migration_attempts WHERE status = 'succeeded'").Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 6 {
		t.Fatalf("unexpected successful PostgreSQL migration attempts: %d", attempts)
	}
	var checksumCount int
	if err := firstDB.QueryRowContext(ctx,
		"SELECT count(*) FROM registry_migration_checksums").Scan(&checksumCount); err != nil {
		t.Fatal(err)
	}
	if checksumCount != 6 {
		t.Fatalf("unexpected PostgreSQL migration checksum count: %d", checksumCount)
	}
}
