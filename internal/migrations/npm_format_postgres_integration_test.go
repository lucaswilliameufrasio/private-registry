//go:build integration

package migrations

import (
	"context"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/testinfra"
)

func TestPostgresNPMFormatUpgradePreservesExistingReferences(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exerciseNPMFormatUpgrade(t, ctx, db, cfg, fail)
			if !fail {
				exerciseNPMCatalogConstraints(t, ctx, db, cfg.DatabaseDriver)
			}
		})
	}
}

func TestPostgresNPMCatalogUpgradeAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			exercisePostgresNPMCatalogUpgrade(t, fail)
		})
	}
}

func exercisePostgresNPMCatalogUpgrade(t *testing.T, fail bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Stop(); err != nil {
			t.Errorf("stop PostgreSQL fixture: %v", err)
		}
	}()
	cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exerciseNPMCatalogUpgrade(t, ctx, db, cfg, fail)
}

func TestPostgresNPMTokenMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exerciseNPMTokenMigration(t, ctx, db, cfg, fail)
		})
	}
}

func TestPostgresNPMReservationMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exerciseNPMReservationMigration(t, ctx, db, cfg, fail)
		})
	}
}

func TestPostgresNPMReceiptMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exerciseNPMReceiptMigration(t, ctx, db, cfg, fail)
		})
	}
}

func TestPostgresNPMReviewMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exerciseNPMReviewMigration(t, ctx, db, cfg, fail)
		})
	}
}

func TestPostgresNPMPublicationMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exerciseNPMPublicationMigration(t, ctx, db, cfg, fail)
		})
	}
}

func TestPostgresNPMDistTagMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exerciseNPMDistTagMigration(t, ctx, db, cfg, fail)
		})
	}
}

func TestPostgresPubFormatUpgrade(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exercisePubFormatUpgrade(t, ctx, db, cfg, fail)
		})
	}
}

func TestPostgresPubCatalogMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exercisePubCatalogMigration(t, ctx, db, cfg, fail)
		})
	}
}

func TestPostgresPubWriteTokenMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exercisePubWriteTokenMigration(t, ctx, db, cfg, fail)
		})
	}
}

func TestPostgresPubReservationMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exercisePubReservationMigration(t, ctx, db, cfg, fail)
		})
	}
}

func TestPostgresPubReceiptMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exercisePubReceiptMigration(t, ctx, db, cfg, fail)
		})
	}
}

func TestPostgresPubReviewMigration(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade", true: "rollback"}[fail], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			fixture, err := testinfra.StartPostgres(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := fixture.Stop(); err != nil {
					t.Errorf("stop PostgreSQL fixture: %v", err)
				}
			}()
			cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
			db, err := database.Open(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			exercisePubReviewMigration(t, ctx, db, cfg, fail)
		})
	}
}
