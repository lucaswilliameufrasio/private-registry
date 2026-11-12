//go:build integration && linux && amd64

package replication

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/lucaswilliameufrasio/sqlite-replication-go/storages3"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/spikes/remotebackup"
	"private-registry/internal/spikes/testinfra"
)

type replicationFixture struct {
	ctx      context.Context
	store    *storages3.Store
	client   *s3.Client
	bucket   string
	database string
	db       *sql.DB
	root     string
}

func newReplicationFixture(t *testing.T) replicationFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	floci, err := testinfra.StartFloci(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := floci.Stop(); err != nil {
			t.Error(err)
		}
	})
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, floci.Endpoint+"/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("isolated Floci did not become ready")
		case <-time.After(50 * time.Millisecond):
		}
	}
	client, err := remotebackup.NewClient(floci.Endpoint, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	bucket := "synthetic-" + uuid.NewString()
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	store, err := storages3.New(client, bucket)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "registry.sqlite")
	// The same connection settings the registry uses: WAL, FULL sync,
	// busy_timeout and SQLite's default autocheckpoint.
	db, err := database.Open(ctx, config.Config{DataDir: dataDir, DatabaseDriver: config.SQLite, DatabaseDSN: path, DatabaseMaxOpenConns: 4, Replication: config.ReplicationConfig{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, `CREATE TABLE entries (id INTEGER PRIMARY KEY, writer INTEGER NOT NULL, payload BLOB NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	return replicationFixture{ctx: ctx, store: store, client: client, bucket: bucket, database: path, db: db, root: root}
}

func (f replicationFixture) replicator(t *testing.T, directory string, rotate, retain int) *Replicator {
	t.Helper()
	replicator, err := New(Options{DatabasePath: f.database, Directory: filepath.Join(f.root, directory), Store: f.store, Prefix: "registry/dr", RemoteID: "synthetic-floci", Interval: time.Hour, RotateAfterCaptures: rotate, RetainGenerations: retain, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return replicator
}

func (f replicationFixture) insert(t *testing.T, writer, count int) {
	t.Helper()
	if err := f.tryInsert(writer, count); err != nil {
		t.Fatal(err)
	}
}

func (f replicationFixture) tryInsert(writer, count int) error {
	for index := 0; index < count; index++ {
		if _, err := f.db.ExecContext(f.ctx, `INSERT INTO entries (writer, payload) VALUES (?, ?)`, writer, bytes.Repeat([]byte{byte(index)}, 2048)); err != nil {
			return fmt.Errorf("writer %d insert %d: %w", writer, index, err)
		}
	}
	return nil
}

// fingerprint summarizes every row so a restored copy can be compared with
// the source.
func fingerprint(t *testing.T, ctx context.Context, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count, writers, bytesTotal int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(writer), 0), COALESCE(SUM(length(payload)), 0) FROM entries`).Scan(&count, &writers, &bytesTotal); err != nil {
		t.Fatal(err)
	}
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("integrity check of %s: %q %v", path, integrity, err)
	}
	return fmt.Sprintf("rows=%d writers=%d bytes=%d", count, writers, bytesTotal)
}

func (f replicationFixture) restore(t *testing.T, name string) (string, Restored) {
	t.Helper()
	destination := filepath.Join(f.root, name, "registry.sqlite")
	if err := os.Mkdir(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	restored, err := Restore(f.ctx, f.store, "registry/dr", destination)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("restored database mode: %v %v", info, err)
	}
	return destination, restored
}

func (f replicationFixture) generations(t *testing.T) []string {
	t.Helper()
	names, _, err := listGenerations(f.ctx, f.store, "registry/dr")
	if err != nil {
		t.Fatal(err)
	}
	return names
}

func TestReplicationRestoresEveryCommittedWrite(t *testing.T) {
	f := newReplicationFixture(t)
	replicator := f.replicator(t, "spool", 1000, 2)
	f.insert(t, 1, 20)
	if err := replicator.Cycle(f.ctx); err != nil {
		t.Fatal(err)
	}
	first := replicator.Status()
	if health, _ := first.Evaluate(time.Now()); first.Generation == "" || first.TXID == 0 || first.LastSyncedAt.IsZero() || health != HealthCurrent {
		t.Fatalf("status after the first cycle: %+v", first)
	}

	// An idle database costs nothing: no capture and no upload.
	if err := replicator.Cycle(f.ctx); err != nil {
		t.Fatal(err)
	}
	if idle := replicator.Status(); idle.TXID != first.TXID || !idle.LastSyncedAt.Equal(first.LastSyncedAt) {
		t.Fatalf("idle cycle replicated something: %+v", idle)
	}

	// Writers keep committing while captures run. Captures exclude them at
	// the SQLite level, so they wait on busy_timeout and must not fail.
	var writers sync.WaitGroup
	writeErrors := make(chan error, 3)
	for writer := 2; writer <= 4; writer++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			writeErrors <- f.tryInsert(writer, 150)
		}()
	}
	done := make(chan struct{})
	go func() {
		writers.Wait()
		close(done)
	}()
	cycles := 0
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
			if err := replicator.Cycle(f.ctx); err != nil {
				t.Fatalf("cycle during concurrent writes: %v", err)
			}
			cycles++
			// Far more aggressive than the one-second minimum interval, but
			// not a tight loop: SQLite does not hand its write lock out
			// fairly, and back-to-back captures would starve the writers.
			time.Sleep(25 * time.Millisecond)
		}
	}
	if cycles == 0 {
		t.Fatal("no capture overlapped the concurrent writers")
	}
	for writer := 0; writer < 3; writer++ {
		if err := <-writeErrors; err != nil {
			t.Fatalf("a registry write failed while replication was running: %v", err)
		}
	}

	// A checkpoint that truncates the WAL between captures removes the
	// frames the next capture would have read; the commits must still arrive.
	f.insert(t, 5, 30)
	if _, err := f.db.ExecContext(f.ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	f.insert(t, 6, 10)
	if err := replicator.Cycle(f.ctx); err != nil {
		t.Fatal(err)
	}
	if after := replicator.Status(); after.TXID <= first.TXID || after.Generation != first.Generation {
		t.Fatalf("status after writes: %+v (first %+v)", after, first)
	}

	source := fingerprint(t, f.ctx, f.database)
	destination, restored := f.restore(t, "restored")
	if got := fingerprint(t, f.ctx, destination); got != source || !strings.Contains(source, "rows=510") {
		t.Fatalf("restored database differs: restored %s, source %s", got, source)
	}
	if restored.Generation != first.Generation || len(restored.Skipped) != 0 {
		t.Fatalf("restore outcome: %+v", restored)
	}
	if _, err := Restore(f.ctx, f.store, "registry/dr", destination); err == nil {
		t.Fatal("restore overwrote an existing database")
	}

	// Writes after the last cycle are exactly what a disaster would lose.
	f.insert(t, 7, 5)
	lagging, _ := f.restore(t, "lagging")
	if got := fingerprint(t, f.ctx, lagging); got != source {
		t.Fatalf("restore included writes that were never replicated: %s", got)
	}
}

func TestReplicationRotatesGenerationsAndSurvivesRestart(t *testing.T) {
	f := newReplicationFixture(t)
	replicator := f.replicator(t, "spool", 2, 2)
	var seen []string
	for round := 0; round < 9; round++ {
		f.insert(t, round, 10)
		if err := replicator.Cycle(f.ctx); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if generation := replicator.Status().Generation; len(seen) == 0 || seen[len(seen)-1] != generation {
			seen = append(seen, generation)
		}
	}
	if len(seen) < 3 {
		t.Fatalf("generations did not rotate: %v", seen)
	}
	remote := f.generations(t)
	if len(remote) != 2 || remote[1] != seen[len(seen)-1] || remote[0] != seen[len(seen)-2] {
		t.Fatalf("retention kept %v, want the last two of %v", remote, seen)
	}
	local, err := os.ReadDir(filepath.Join(f.root, "spool"))
	if err != nil || len(local) != 1 || local[0].Name() != seen[len(seen)-1] {
		t.Fatalf("local spool holds %v, want only the current generation (%v)", local, err)
	}

	// A new process starts a new generation from a full snapshot instead of
	// trusting the spool left behind, including writes made while it was down.
	f.insert(t, 100, 25)
	restarted := f.replicator(t, "spool", 2, 2)
	if err := restarted.Cycle(f.ctx); err != nil {
		t.Fatal(err)
	}
	current := restarted.Status().Generation
	if current <= seen[len(seen)-1] {
		t.Fatalf("restart reused generation %s", current)
	}
	source := fingerprint(t, f.ctx, f.database)
	destination, restored := f.restore(t, "after-restart")
	if got := fingerprint(t, f.ctx, destination); got != source || restored.Generation != current {
		t.Fatalf("restore after restart: %s from %s, want %s from %s", got, restored.Generation, source, current)
	}

	// A process that died before finishing its first upload leaves a newer,
	// unusable generation. Restore falls back to the newest complete one and
	// reports what it skipped; the next successful generation supersedes it.
	broken := time.Now().UTC().Add(time.Second).Format(generationLayout) + "-deadbeef"
	if _, err := f.client.PutObject(f.ctx, &s3.PutObjectInput{Bucket: aws.String(f.bucket), Key: aws.String("registry/dr/generations/" + broken + "/ltx/0/0000000000000001-0000000000000001.ltx"), Body: strings.NewReader("truncated upload")}); err != nil {
		t.Fatal(err)
	}
	// An object this package did not name is never listed and never deleted.
	foreign := "registry/dr/generations/operator-notes/readme.txt"
	if _, err := f.client.PutObject(f.ctx, &s3.PutObjectInput{Bucket: aws.String(f.bucket), Key: aws.String(foreign), Body: strings.NewReader("keep me")}); err != nil {
		t.Fatal(err)
	}
	fallback, outcome := f.restore(t, "fallback")
	if got := fingerprint(t, f.ctx, fallback); got != source || outcome.Generation != current || len(outcome.Skipped) != 1 || outcome.Skipped[0] != broken {
		t.Fatalf("fallback restore: %s %+v", got, outcome)
	}
	time.Sleep(1100 * time.Millisecond)
	f.insert(t, 101, 5)
	later := f.replicator(t, "spool", 2, 2)
	if err := later.Cycle(f.ctx); err != nil {
		t.Fatal(err)
	}
	remote = f.generations(t)
	if len(remote) != 2 || remote[1] != later.Status().Generation {
		t.Fatalf("generations after superseding the broken one: %v", remote)
	}
	if _, err := f.client.HeadObject(f.ctx, &s3.HeadObjectInput{Bucket: aws.String(f.bucket), Key: aws.String(foreign)}); err != nil {
		t.Fatalf("pruning deleted an object it does not own: %v", err)
	}
}

func TestReplicationRecoversFromDestinationOutage(t *testing.T) {
	f := newReplicationFixture(t)
	missing, err := storages3.New(f.client, "synthetic-missing-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	options := Options{DatabasePath: f.database, Directory: filepath.Join(f.root, "spool"), Store: missing, Prefix: "registry/dr", RemoteID: "synthetic-floci", Interval: time.Hour, RotateAfterCaptures: 1000, RetainGenerations: 2, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	replicator, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.insert(t, 1, 10)
	for attempt := 1; attempt <= 2; attempt++ {
		if err := replicator.Cycle(f.ctx); err == nil {
			t.Fatal("upload to a missing bucket succeeded")
		}
		if status := replicator.Status(); status.ConsecutiveFails != attempt || status.LastError == "" || !status.LastSyncedAt.IsZero() || func() bool { health, _ := status.Evaluate(time.Now()); return health != HealthFailing }() {
			t.Fatalf("status during outage: %+v", status)
		}
	}
	// The registry keeps accepting writes while the destination is down.
	f.insert(t, 2, 10)
	replicator.options.Store = f.store
	if err := replicator.Cycle(f.ctx); err != nil {
		t.Fatal(err)
	}
	if status := replicator.Status(); status.ConsecutiveFails != 0 || status.LastError != "" || status.LastSyncedAt.IsZero() {
		t.Fatalf("status after recovery: %+v", status)
	}
	destination, _ := f.restore(t, "restored")
	if got, want := fingerprint(t, f.ctx, destination), fingerprint(t, f.ctx, f.database); got != want {
		t.Fatalf("restore after outage: %s, want %s", got, want)
	}
}
