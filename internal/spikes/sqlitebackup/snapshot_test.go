package sqlitebackup

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dsn, err := DSN(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	_, err = db.Exec(`CREATE TABLE data(id INTEGER PRIMARY KEY, payload BLOB);
		WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 128)
		INSERT INTO data(payload) SELECT zeroblob(2048) FROM n;`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestExperimentRealDatabase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	report, err := Experiment(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if report.WritesDuring != 3 || report.RestoredRows != 131 || report.Progress.Remaining != 0 || report.Integrity != "ok" {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.SnapshotSHA256 != report.RestoredSHA256 || report.RemoteValidated {
		t.Fatalf("invalid integrity or fictitious remote validation: %+v", report)
	}
}

func TestExperimentEscapesFilePaths(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "backup ?#%")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := Experiment(ctx, directory); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseConnectionSettings(t *testing.T) {
	db := testDatabase(t)
	db.SetMaxOpenConns(2)
	ctx := context.Background()
	first, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	for _, conn := range []*sql.Conn{first, second} {
		var journal string
		var foreignKeys, sync int
		for _, setting := range []struct {
			query string
			value any
		}{
			{"PRAGMA journal_mode", &journal},
			{"PRAGMA foreign_keys", &foreignKeys},
			{"PRAGMA synchronous", &sync},
		} {
			if err := conn.QueryRowContext(ctx, setting.query).Scan(setting.value); err != nil {
				t.Fatal(err)
			}
		}
		if journal != "wal" || foreignKeys != 1 || sync != 2 {
			t.Fatalf("wrong connection settings: %s %d %d", journal, foreignKeys, sync)
		}
	}
}

func TestSnapshotDoesNotOverwrite(t *testing.T) {
	db := testDatabase(t)
	path := filepath.Join(t.TempDir(), "snapshot.db")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Snapshot(ctx, db, path, Options{PagesPerStep: 8}); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected destination conflict, got %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep" {
		t.Fatalf("existing destination changed: %q %v", data, err)
	}
}

func TestSnapshotCancellationRemovesPartial(t *testing.T) {
	db := testDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "partial.db")
	progress, err := Snapshot(ctx, db, path, Options{
		PagesPerStep: 1,
		AfterStep: func(p Progress) error {
			if p.Remaining == 0 {
				t.Fatal("fixture did not produce a partial snapshot")
			}
			cancel()
			return nil
		},
	})
	if !errors.Is(err, context.Canceled) || progress.Steps != 1 {
		t.Fatalf("expected cancellation after one step: %+v %v", progress, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial snapshot retained: %v", err)
	}
	if _, err := db.Exec("INSERT INTO data(payload) VALUES('after cancellation')"); err != nil {
		t.Fatalf("backup resources were not released: %v", err)
	}
}

func TestSnapshotTimeoutAndObserverFailure(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "observer", true: "deadline"}[timeout], func(t *testing.T) {
			db := testDatabase(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			marker := errors.New("observer failure")
			options := Options{PagesPerStep: 1, AfterStep: func(Progress) error { return marker }}
			if timeout {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Millisecond)
				defer cancel()
				marker = context.DeadlineExceeded
				options.AfterStep = nil
				options.Pause = time.Second
			}
			path := filepath.Join(t.TempDir(), "failed.db")
			if _, err := Snapshot(ctx, db, path, options); !errors.Is(err, marker) {
				t.Fatalf("expected %v, got %v", marker, err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed destination retained: %v", err)
			}
		})
	}
}

func TestSnapshotValidation(t *testing.T) {
	db := testDatabase(t)
	bounded, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		db   *sql.DB
		opts Options
	}{
		{"nil database", bounded, nil, Options{PagesPerStep: 8}},
		{"unbounded", context.Background(), db, Options{PagesPerStep: 8}},
		{"zero pages", bounded, db, Options{}},
		{"negative pause", bounded, db, Options{PagesPerStep: 8, Pause: -time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invalid.db")
			if _, err := Snapshot(tc.ctx, tc.db, path, tc.opts); err == nil {
				t.Fatal("invalid input accepted")
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid request created a file: %v", err)
			}
		})
	}
}

func TestSnapshotClosedDatabase(t *testing.T) {
	db := testDatabase(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "closed.db")
	if _, err := Snapshot(ctx, db, path, Options{PagesPerStep: 8}); err == nil {
		t.Fatal("closed database accepted")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed snapshot retained: %v", err)
	}
}
