// Package replication continuously ships the registry's SQLite database to an
// S3-compatible bucket for disaster recovery, using sqlite-replication-go.
//
// The library keeps every incremental segment of a repository forever and
// replays the whole chain on each capture, so this package bounds that chain
// with generations: every process start and every RotateAfterCaptures captures
// begin a new generation with a fresh full snapshot under its own remote
// prefix. Older generations are deleted from the bucket only after a newer one
// has been completely uploaded.
//
// Scope: the database only. Package objects, the master key and configuration
// are not replicated here.
package replication

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	sqlitereplication "github.com/lucaswilliameufrasio/sqlite-replication-go"
	"github.com/lucaswilliameufrasio/sqlite-replication-go/replicator"
	"github.com/lucaswilliameufrasio/sqlite-replication-go/storages3"
)

const (
	generationsSegment  = "generations"
	generationLayout    = "20060102T150405.000000000Z"
	maxCaptureFailures  = 3
	finalFlushTimeout   = 30 * time.Second
	captureLockPatience = 15 * time.Second
	maxListedGeneration = 100000
)

type Options struct {
	// DatabasePath is the live SQLite database in WAL mode.
	DatabasePath string
	// Directory holds the local spool. Everything in it is derived from the
	// database and is recreated on start.
	Directory string
	Store     *storages3.Store
	// Prefix is the operator's key prefix inside the bucket; may be empty.
	Prefix string
	// RemoteID identifies the destination in the library's local
	// acknowledgement; it must be stable and must not be secret.
	RemoteID            string
	Interval            time.Duration
	RotateAfterCaptures int
	RetainGenerations   int
	Logger              *slog.Logger
}

// Status is a point-in-time view for operators and tests.
type Status struct {
	Generation       string
	TXID             uint64
	LastSyncedAt     time.Time
	ConsecutiveFails int
	LastError        string
	// LastCycleAt is when the last cycle ended, successful or not.
	LastCycleAt time.Time
	StartedAt   time.Time
	Interval    time.Duration
}

// Health classifies replication for operators. A database that did not
// change is not lagging: lag is measured from the last cycle that had nothing
// left to send, which is the last moment the bucket was known to be current.
type Health string

const (
	HealthCurrent Health = "current"
	HealthPending Health = "pending" // no generation uploaded yet
	HealthLagging Health = "lagging"
	HealthFailing Health = "failing"
)

// Evaluate reports the health at now. Replication is lagging when the bucket
// was last known to be current more than three intervals ago, and failing
// when the most recent cycles failed.
func (s Status) Evaluate(now time.Time) (Health, time.Duration) {
	if s.ConsecutiveFails > 0 {
		reference := s.LastCurrentAt()
		if reference.IsZero() {
			reference = s.StartedAt
		}
		return HealthFailing, now.Sub(reference)
	}
	reference := s.LastCurrentAt()
	if reference.IsZero() {
		return HealthPending, now.Sub(s.StartedAt)
	}
	lag := now.Sub(reference)
	if s.Interval > 0 && lag > 3*s.Interval {
		return HealthLagging, lag
	}
	return HealthCurrent, lag
}

// LastCurrentAt is the last time the bucket held every committed change.
func (s Status) LastCurrentAt() time.Time {
	if s.ConsecutiveFails == 0 && !s.LastSyncedAt.IsZero() && s.LastCycleAt.After(s.LastSyncedAt) {
		return s.LastCycleAt
	}
	return s.LastSyncedAt
}

type Replicator struct {
	options Options

	mu     sync.Mutex
	status Status

	// The fields below are only touched by the goroutine running Cycle.
	generation string
	captures   int
	pending    bool
	observed   fileState
	pruned     bool
}

type fileState struct {
	databaseSize, walSize   int64
	databaseTime, walTime   time.Time
	databaseSeen, walExists bool
}

func New(options Options) (*Replicator, error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, errors.New("SQLite replication is only supported on Linux amd64")
	}
	if options.Store == nil || options.Logger == nil || !filepath.IsAbs(options.DatabasePath) || !filepath.IsAbs(options.Directory) || strings.TrimSpace(options.RemoteID) == "" || options.Interval <= 0 || options.RotateAfterCaptures < 1 || options.RetainGenerations < 2 {
		return nil, errors.New("SQLite replication configuration is invalid")
	}
	if strings.Trim(options.Prefix, "/") != options.Prefix {
		return nil, errors.New("SQLite replication prefix is invalid")
	}
	if err := os.MkdirAll(options.Directory, 0o700); err != nil {
		return nil, errors.New("SQLite replication directory could not be created")
	}
	info, err := os.Lstat(options.Directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("SQLite replication directory must be a private directory")
	}
	return &Replicator{options: options, status: Status{StartedAt: time.Now().UTC(), Interval: options.Interval}}, nil
}

func (r *Replicator) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

// Run replicates until ctx is cancelled, then makes one last bounded attempt
// so that a graceful shutdown ships the final transactions.
func (r *Replicator) Run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), finalFlushTimeout)
			r.cycle(flushCtx, true)
			cancel()
			return
		case <-timer.C:
			r.cycle(ctx, false)
			timer.Reset(r.options.Interval)
		}
	}
}

// Cycle runs one capture-and-upload round. It is exported for tests and for
// callers that drive replication themselves.
func (r *Replicator) Cycle(ctx context.Context) error {
	return r.cycle(ctx, false)
}

func (r *Replicator) cycle(ctx context.Context, final bool) error {
	err := r.replicateOnce(ctx, final)
	r.mu.Lock()
	r.status.LastCycleAt = time.Now().UTC()
	if err != nil {
		r.status.ConsecutiveFails++
		r.status.LastError = err.Error()
	} else {
		r.status.ConsecutiveFails = 0
		r.status.LastError = ""
	}
	failures := r.status.ConsecutiveFails
	r.mu.Unlock()
	if err != nil {
		if ctx.Err() != nil && !final {
			return err
		}
		// The local spool is fully derivable from the database, so repeated
		// failures are answered by starting over with a new full snapshot
		// instead of trusting a possibly inconsistent chain.
		if failures >= maxCaptureFailures && !sqliteBusy(err) {
			r.generation = ""
		}
		level := slog.LevelWarn
		if failures >= maxCaptureFailures {
			level = slog.LevelError
		}
		r.options.Logger.Log(context.Background(), level, "SQLite replication cycle failed", "error", err, "consecutive_failures", failures, "generation", r.generation)
	}
	return err
}

func (r *Replicator) replicateOnce(ctx context.Context, final bool) error {
	before, err := observe(r.options.DatabasePath)
	if err != nil {
		return err
	}
	if r.generation == "" || (r.captures >= r.options.RotateAfterCaptures && !final) {
		if err := r.startGeneration(ctx); err != nil {
			return err
		}
		r.observed = before
	} else if before != r.observed {
		result, err := r.capture(ctx)
		if err != nil {
			return fmt.Errorf("capture SQLite changes: %w", err)
		}
		r.captures++
		r.pending = true
		r.observed = before
		r.options.Logger.Debug("SQLite changes captured", "generation", r.generation, "txid", result.TXID, "transactions", result.Transactions)
	}
	if !r.pending {
		return nil
	}
	synced, err := replicator.SyncToS3(ctx, r.directory(), r.options.Store, r.remotePrefix(r.generation), r.options.RemoteID)
	if err != nil {
		return fmt.Errorf("upload SQLite replication chain: %w", err)
	}
	r.pending = false
	r.mu.Lock()
	r.status.Generation = r.generation
	r.status.TXID = synced.TXID
	r.status.LastSyncedAt = time.Now().UTC()
	r.mu.Unlock()
	if !r.pruned {
		// Only now is the current generation a complete restore point, so
		// only now may older ones leave the bucket.
		if err := r.prune(ctx); err != nil {
			return fmt.Errorf("prune old SQLite replication generations: %w", err)
		}
		r.pruned = true
	}
	return nil
}

// sqliteLeaseGate satisfies the library's mandatory write gate without an
// in-process pause. The capture itself holds BEGIN IMMEDIATE on the database
// for its whole duration, which excludes every other writer at the SQLite
// level; the registry's own connections wait on busy_timeout. A commit that
// the registry checkpoints between two captures is recovered by the library's
// image reconciliation rather than from the WAL. The consequence of not
// pausing in-process is latency, not loss: a write that waits longer than
// busy_timeout for a slow capture fails with SQLITE_BUSY and is retried by the
// client.
func sqliteLeaseGate(context.Context) (func() error, error) {
	return func() error { return nil }, nil
}

// capture retries while the registry holds SQLite's write lock. The library
// asks for the lock without waiting and reports SQLITE_BUSY before touching
// its spool, so trying again is safe; the pause is short because registry
// transactions are short and the lock is not handed out fairly.
func (r *Replicator) capture(ctx context.Context) (replicator.CaptureResult, error) {
	deadline := time.Now().Add(captureLockPatience)
	pause := time.Millisecond
	for {
		result, err := replicator.CaptureOnce(ctx, r.options.DatabasePath, r.directory(), sqliteLeaseGate)
		if err == nil || !sqliteBusy(err) || time.Now().After(deadline) {
			return result, err
		}
		select {
		case <-ctx.Done():
			return replicator.CaptureResult{}, ctx.Err()
		case <-time.After(pause):
		}
		if pause < 20*time.Millisecond {
			pause *= 2
		}
	}
}

// sqliteBusy reports SQLITE_BUSY and its extended codes.
func sqliteBusy(err error) bool {
	var coded interface{ Code() int }
	return errors.As(err, &coded) && coded.Code()&0xff == 5
}

func (r *Replicator) startGeneration(ctx context.Context) error {
	entries, err := os.ReadDir(r.options.Directory)
	if err != nil {
		return errors.New("SQLite replication directory could not be read")
	}
	for _, entry := range entries {
		if _, err := time.Parse(generationLayout, generationTime(entry.Name())); err != nil || !entry.IsDir() {
			continue
		}
		if err := os.RemoveAll(filepath.Join(r.options.Directory, entry.Name())); err != nil {
			return errors.New("previous SQLite replication spool could not be removed")
		}
	}
	name, err := newGenerationName()
	if err != nil {
		return err
	}
	directory := filepath.Join(r.options.Directory, name)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return errors.New("SQLite replication generation directory could not be created")
	}
	if _, err := sqlitereplication.Snapshot(ctx, r.options.DatabasePath, directory); err != nil {
		_ = os.RemoveAll(directory)
		return fmt.Errorf("snapshot SQLite database: %w", err)
	}
	r.generation, r.captures, r.pending, r.pruned = name, 0, true, false
	r.options.Logger.Info("SQLite replication generation started", "generation", name)
	return nil
}

func (r *Replicator) directory() string {
	return filepath.Join(r.options.Directory, r.generation)
}

func (r *Replicator) remotePrefix(generation string) string {
	return generationPrefix(r.options.Prefix, generation)
}

func generationsRoot(prefix string) string {
	if prefix == "" {
		return generationsSegment
	}
	return prefix + "/" + generationsSegment
}

func generationPrefix(prefix, generation string) string {
	return generationsRoot(prefix) + "/" + generation
}

// newGenerationName sorts chronologically; the random suffix keeps two starts
// within the same nanosecond apart.
func newGenerationName() (string, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", errors.New("SQLite replication generation name could not be created")
	}
	return time.Now().UTC().Format(generationLayout) + "-" + hex.EncodeToString(suffix[:]), nil
}

func generationTime(name string) string {
	stamp, _, _ := strings.Cut(name, "-")
	return stamp
}

func validGeneration(name string) bool {
	stamp, suffix, found := strings.Cut(name, "-")
	if !found || len(suffix) != 8 {
		return false
	}
	if _, err := hex.DecodeString(suffix); err != nil {
		return false
	}
	_, err := time.Parse(generationLayout, stamp)
	return err == nil
}

// listGenerations returns every generation with at least one object, oldest
// first, together with the keys found for each.
func listGenerations(ctx context.Context, store *storages3.Store, prefix string) ([]string, map[string][]string, error) {
	root := generationsRoot(prefix) + "/"
	keys := make(map[string][]string)
	var cursor *string
	for {
		page, err := store.ListPage(ctx, root, cursor, 1000)
		if err != nil {
			return nil, nil, fmt.Errorf("list SQLite replication generations: %w", err)
		}
		for _, object := range page.Contents {
			if object.Key == nil || !strings.HasPrefix(*object.Key, root) {
				continue
			}
			name, _, found := strings.Cut(strings.TrimPrefix(*object.Key, root), "/")
			// Keys this package did not name are never listed and therefore
			// never deleted.
			if !found || !validGeneration(name) {
				continue
			}
			keys[name] = append(keys[name], *object.Key)
		}
		if len(keys) > maxListedGeneration {
			return nil, nil, errors.New("SQLite replication bucket holds an unexpected number of generations")
		}
		if page.NextContinuationToken == nil || *page.NextContinuationToken == "" {
			break
		}
		cursor = page.NextContinuationToken
	}
	names := make([]string, 0, len(keys))
	for name := range keys {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, keys, nil
}

// prune keeps the newest RetainGenerations generations, always including the
// one that was just uploaded, and deletes the objects of the rest.
func (r *Replicator) prune(ctx context.Context) error {
	names, keys, err := listGenerations(ctx, r.options.Store, r.options.Prefix)
	if err != nil {
		return err
	}
	keep := make(map[string]struct{}, r.options.RetainGenerations)
	keep[r.generation] = struct{}{}
	for index := len(names) - 1; index >= 0 && len(keep) < r.options.RetainGenerations; index-- {
		// A generation newer than the current one cannot be ours; it is left
		// alone and does not use up the retention budget.
		if names[index] <= r.generation {
			keep[names[index]] = struct{}{}
		}
	}
	for _, name := range names {
		if _, retained := keep[name]; retained || name > r.generation {
			continue
		}
		objects := keys[name]
		for start := 0; start < len(objects); start += 1000 {
			end := min(start+1000, len(objects))
			if err := r.options.Store.DeleteBatch(ctx, objects[start:end]); err != nil {
				return fmt.Errorf("delete superseded SQLite replication generation: %w", err)
			}
		}
		r.options.Logger.Info("SQLite replication generation removed", "generation", name, "objects", len(objects))
	}
	return nil
}

// Restored describes what Restore wrote.
type Restored struct {
	Generation string
	// Skipped lists newer generations that could not be restored, typically
	// because the process died before their first upload completed.
	Skipped []string
}

// Restore rebuilds the newest restorable database state from the bucket into
// destination, which must not exist. The library verifies the chain and the
// SQLite image before the file appears; nothing is overwritten.
func Restore(ctx context.Context, store *storages3.Store, prefix, destination string) (Restored, error) {
	if store == nil || !filepath.IsAbs(destination) {
		return Restored{}, errors.New("SQLite restore parameters are invalid")
	}
	if _, err := os.Lstat(destination); err == nil {
		return Restored{}, errors.New("SQLite restore destination already exists; refusing to overwrite it")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Restored{}, errors.New("SQLite restore destination could not be checked")
	}
	names, _, err := listGenerations(ctx, store, prefix)
	if err != nil {
		return Restored{}, err
	}
	if len(names) == 0 {
		return Restored{}, errors.New("no SQLite replication generation exists under the configured bucket and prefix")
	}
	now := time.Now().UnixMilli()
	var result Restored
	var failures []error
	for index := len(names) - 1; index >= 0; index-- {
		name := names[index]
		err := replicator.RestoreFromS3(ctx, store, generationPrefix(prefix, name), destination, replicator.RestoreTarget{TimestampMillis: &now})
		if err == nil {
			if err := os.Chmod(destination, 0o600); err != nil {
				return Restored{}, errors.New("restored SQLite database permissions could not be set")
			}
			result.Generation = name
			return result, nil
		}
		if ctx.Err() != nil {
			return Restored{}, ctx.Err()
		}
		result.Skipped = append(result.Skipped, name)
		failures = append(failures, fmt.Errorf("generation %s: %w", name, err))
	}
	return Restored{}, errors.Join(append([]error{errors.New("no SQLite replication generation could be restored")}, failures...)...)
}

func observe(databasePath string) (fileState, error) {
	var state fileState
	info, err := os.Stat(databasePath)
	if err != nil {
		return fileState{}, errors.New("SQLite database could not be inspected for replication")
	}
	state.databaseSeen, state.databaseSize, state.databaseTime = true, info.Size(), info.ModTime()
	wal, err := os.Stat(databasePath + "-wal")
	if err == nil {
		state.walExists, state.walSize, state.walTime = true, wal.Size(), wal.ModTime()
	} else if !errors.Is(err, os.ErrNotExist) {
		return fileState{}, errors.New("SQLite WAL could not be inspected for replication")
	}
	return state, nil
}
