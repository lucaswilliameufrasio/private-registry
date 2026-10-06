//go:build integration

package ociprobe

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"modernc.org/sqlite"
)

func releaseConnections(t *testing.T, timeout int) (*sql.DB, *sql.DB) {
	t.Helper()
	uri := &url.URL{Scheme: "file", Path: filepath.Join(t.TempDir(), "release.db")}
	open := func() *sql.DB {
		db, err := sql.Open("sqlite", fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(%d)", uri.String(), timeout))
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() {
			if err := db.Close(); err != nil {
				t.Error(err)
			}
		})
		if err := db.Ping(); err != nil {
			t.Fatal(err)
		}
		return db
	}
	first := open()
	if _, err := first.Exec(`CREATE TABLE policy(publisher_allowed integer NOT NULL);
		INSERT INTO policy VALUES(1);
		CREATE TABLE attempts(id text PRIMARY KEY, phase text NOT NULL);
		CREATE TABLE candidate_routes(path text PRIMARY KEY, attempt text REFERENCES attempts(id));
		CREATE TABLE visible(path text PRIMARY KEY, attempt text REFERENCES attempts(id));
		INSERT INTO attempts VALUES('attempt','verified');
		INSERT INTO candidate_routes VALUES('/v2/fixture/image/manifests/v1','attempt');`); err != nil {
		t.Fatal(err)
	}
	return first, open()
}

func requireBusy(t *testing.T, err error) {
	t.Helper()
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) || sqliteErr.Code()&0xff != 5 { // SQLITE_BUSY, including extended codes.
		t.Fatalf("expected real SQLite writer contention, got %v", err)
	}
}

func releaseState(t *testing.T, db *sql.DB) (string, int) {
	t.Helper()
	var phase string
	var routes int
	if err := db.QueryRow("SELECT phase FROM attempts WHERE id='attempt'").Scan(&phase); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM visible").Scan(&routes); err != nil {
		t.Fatal(err)
	}
	return phase, routes
}

func TestSQLiteIndependentWritersOrderReleaseAndRevocation(t *testing.T) {
	for _, scenario := range []string{"revocation_first", "release_first", "release_rollback"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			first, second := releaseConnections(t, 0) // Immediate lock errors, no sleeps/retries.
			tx, err := first.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			if scenario == "revocation_first" {
				if _, err := tx.ExecContext(ctx, "UPDATE policy SET publisher_allowed=0"); err != nil {
					t.Fatal(err)
				}
				requireBusy(t, releaseVerified(ctx, second, "attempt"))
				if phase, routes := releaseState(t, second); phase != "verified" || routes != 0 {
					t.Fatal("contending release mutated state:", phase, routes)
				}
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
				if err := releaseVerified(ctx, second, "attempt"); !errors.Is(err, errReleaseIneligible) {
					t.Fatal("release ignored committed revocation:", err)
				}
			} else {
				if err := stageVerifiedRelease(ctx, tx, "attempt"); err != nil {
					t.Fatal(err)
				}
				if phase, routes := releaseState(t, second); phase != "verified" || routes != 0 {
					t.Fatal("reader saw uncommitted release:", phase, routes)
				}
				_, err := second.ExecContext(ctx, "UPDATE policy SET publisher_allowed=0")
				requireBusy(t, err) // A busy update is NOT a revocation acknowledgment.
				if scenario == "release_first" {
					if err := tx.Commit(); err != nil {
						t.Fatal(err)
					}
					if phase, routes := releaseState(t, second); phase != "published" || routes != 1 {
						t.Fatal("committed release missing:", phase, routes)
					}
				} else if err := tx.Rollback(); err != nil {
					t.Fatal(err)
				}
				// Explicit new operation after the first transaction is resolved;
				// not an automatic SQL retry that hides an unknown commit outcome.
				if _, err := second.ExecContext(ctx, "UPDATE policy SET publisher_allowed=0"); err != nil {
					t.Fatal(err)
				}
			}
			phase, routes := releaseState(t, second)
			if scenario != "release_first" && (phase != "verified" || routes != 0) {
				t.Fatal("failed/rolled-back release became visible:", phase, routes)
			}
			if _, err := second.ExecContext(ctx, `INSERT INTO attempts VALUES('later','verified');
				INSERT INTO candidate_routes VALUES('/v2/fixture/image/manifests/later','later')`); err != nil {
				t.Fatal(err)
			}
			if err := releaseVerified(ctx, first, "later"); !errors.Is(err, errReleaseIneligible) {
				t.Fatal("later release ignored acknowledged revocation:", err)
			}
		})
	}
}

func TestSQLiteConcurrentReleaseAndRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	first, second := releaseConnections(t, 5000)
	for iteration := 0; iteration < 20; iteration++ {
		if _, err := first.ExecContext(ctx, `DELETE FROM visible; UPDATE attempts SET phase='verified';
			UPDATE policy SET publisher_allowed=1`); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		released, revoked := make(chan error, 1), make(chan error, 1)
		go func() {
			<-start
			released <- releaseVerified(ctx, first, "attempt")
		}()
		go func() {
			<-start
			_, err := second.ExecContext(ctx, "UPDATE policy SET publisher_allowed=0")
			revoked <- err
		}()
		close(start)
		var releaseErr error
		select {
		case releaseErr = <-released:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		select {
		case err := <-revoked:
			if err != nil {
				t.Fatal("concurrent revocation failed:", err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		phase, routes := releaseState(t, second)
		if releaseErr == nil {
			if phase != "published" || routes != 1 {
				t.Fatal("successful release was not atomic:", phase, routes)
			}
		} else if !errors.Is(releaseErr, errReleaseIneligible) || phase != "verified" || routes != 0 {
			t.Fatal("unexpected concurrent release outcome:", phase, routes, releaseErr)
		}
		// Either committed ordering is valid; no test requires the scheduler to
		// produce both. Deterministic lock cases above establish both orderings.
		if err := releaseVerified(ctx, first, "attempt"); !errors.Is(err, errReleaseIneligible) {
			t.Fatal("post-race release ignored revocation:", err)
		}
	}
}
