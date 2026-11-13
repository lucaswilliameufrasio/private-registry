package authattempts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
)

type sqliteFixture struct {
	db      *sql.DB
	limiter *Limiter
	now     time.Time
}

func newSQLiteFixture(t *testing.T) *sqliteFixture {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "registry-data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		DataDir:              dataDir,
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          filepath.Join(dataDir, "registry.sqlite"),
		DatabaseMaxOpenConns: 8,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test SQLite database: %v", err)
		}
	})
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	limiter, err := New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &sqliteFixture{
		db:      db,
		limiter: limiter,
		now:     time.Date(2026, time.October, 19, 12, 0, 0, 0, time.UTC),
	}
	limiter.now = func() time.Time {
		return fixture.now
	}
	return fixture
}

func TestPasswordAttemptLimitsAndSuccessReset(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	for range accountLimit {
		if _, err := fixture.limiter.BeginPassword(ctx, "alice", "192.0.2.10:4000"); err != nil {
			t.Fatalf("attempt below account limit was denied: %v", err)
		}
	}
	retryAfter, err := fixture.limiter.BeginPassword(ctx, "alice", "192.0.2.10:5000")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("account limit was not enforced: %v", err)
	}
	if retryAfter <= 0 || retryAfter > windowDuration {
		t.Fatalf("unexpected retry delay: %s", retryAfter)
	}
	if err := fixture.limiter.CompletePassword(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.limiter.BeginPassword(ctx, "alice", "192.0.2.10"); err != nil {
		t.Fatalf("successful password verification did not reset the account bucket: %v", err)
	}

	var storedBucketKey string
	if err := fixture.db.QueryRowContext(ctx,
		"SELECT bucket_key FROM registry_auth_attempt_buckets WHERE bucket_key = ?", bucketKey("password", "alice")).Scan(&storedBucketKey); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedBucketKey, "alice") || len(storedBucketKey) != 64 {
		t.Fatal("attempt bucket persisted the login identifier instead of its digest")
	}
}

func TestPersonalTokenFailuresAreBoundedAndSeparateFromPassword(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	for range personalTokenSourceLimit - 1 {
		if _, err := fixture.limiter.BeginPersonalToken(ctx, "192.0.2.44:1234"); err != nil {
			t.Fatal("token attempt rejected early:", err)
		}
	}
	if err := fixture.limiter.CompletePersonalToken(ctx, "192.0.2.44"); err != nil {
		t.Fatal("reset after successful token validation:", err)
	}
	for range personalTokenSourceLimit {
		if _, err := fixture.limiter.BeginPersonalToken(ctx, "192.0.2.44"); err != nil {
			t.Fatal("token attempt rejected early:", err)
		}
	}
	if _, err := fixture.limiter.BeginPersonalToken(ctx, "192.0.2.44"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("repeated bad tokens were not rate limited: %v", err)
	}
	if _, err := fixture.limiter.BeginPassword(ctx, "synthetic", "192.0.2.44"); err != nil {
		t.Fatalf("token failures blocked unrelated password bucket: %v", err)
	}
	fixture.now = fixture.now.Add(windowDuration + time.Second)
	if _, err := fixture.limiter.BeginPersonalToken(ctx, "192.0.2.44"); err != nil {
		t.Fatalf("token source did not recover after window: %v", err)
	}
}

func TestSourceLimitIsSharedAcrossAccountsAndMFA(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	for attempt := range sourceLimit {
		loginName := fmt.Sprintf("account-%d", attempt)
		if _, err := fixture.limiter.BeginPassword(ctx, loginName, "192.0.2.11:443"); err != nil {
			t.Fatalf("source attempt %d was denied before the limit: %v", attempt+1, err)
		}
	}
	if _, err := fixture.limiter.BeginMFA(ctx, "a6ba4526-1ed4-473c-9c79-0808b5323a5a", "192.0.2.11"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("source limit was not shared with MFA attempts: %v", err)
	}
}

func TestAttemptWindowExpiresAndBucketCapacityIsBounded(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	for range accountLimit {
		if _, err := fixture.limiter.BeginPassword(ctx, "alice", "192.0.2.12"); err != nil {
			t.Fatal(err)
		}
	}
	fixture.now = fixture.now.Add(windowDuration)
	if _, err := fixture.limiter.BeginPassword(ctx, "alice", "192.0.2.12"); err != nil {
		t.Fatalf("attempt did not become available after the window: %v", err)
	}

	otherFixture := newSQLiteFixture(t)
	otherFixture.limiter.bucketCapacity = 1
	if _, err := otherFixture.limiter.BeginPassword(ctx, "alice", "192.0.2.13"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("bucket table capacity was not enforced: %v", err)
	}
	var count int
	if err := otherFixture.db.QueryRowContext(ctx,
		"SELECT count(*) FROM registry_auth_attempt_buckets").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("capacity rejection left %d buckets, want the admitted source bucket only", count)
	}
}

func TestAttemptWindowIsRollingNotFixedFromFirstFailure(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	for range accountLimit {
		if _, err := fixture.limiter.BeginPassword(ctx, "rolling.user", "192.0.2.15"); err != nil {
			t.Fatal(err)
		}
		fixture.now = fixture.now.Add(3 * time.Minute)
	}
	if _, err := fixture.limiter.BeginPassword(ctx, "rolling.user", "192.0.2.15"); err != nil {
		t.Fatalf("the oldest attempt should expire at the 15-minute boundary: %v", err)
	}
	fixture.now = fixture.now.Add(time.Second)
	if _, err := fixture.limiter.BeginPassword(ctx, "rolling.user", "192.0.2.15"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("recent attempts were cleared as a fixed window instead of rolling: %v", err)
	}
}

func TestConcurrentAttemptsCannotExceedAccountLimit(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	const callers = 12
	start := make(chan struct{})
	type result struct {
		err error
	}
	results := make(chan result, callers)
	var waitGroup sync.WaitGroup
	for range callers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			_, err := fixture.limiter.BeginPassword(ctx, "alice", "192.0.2.14")
			results <- result{err: err}
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)

	admitted := 0
	limited := 0
	for result := range results {
		if result.err == nil {
			admitted++
			continue
		}
		if errors.Is(result.err, ErrRateLimited) {
			limited++
			continue
		}
		t.Fatalf("concurrent attempt returned unexpected error: %v", result.err)
	}
	if admitted != accountLimit || limited != callers-accountLimit {
		t.Fatalf("got %d admitted and %d limited attempts, want %d and %d", admitted, limited, accountLimit, callers-accountLimit)
	}
}

func TestInvalidSourceIsRejected(t *testing.T) {
	fixture := newSQLiteFixture(t)
	if _, err := fixture.limiter.BeginPassword(context.Background(), "alice", "not-an-address"); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("invalid source address was accepted: %v", err)
	}
}

func TestCorruptBucketMetadataFailsClosed(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	now := fixture.now.Unix()
	_, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_auth_attempt_buckets
		(bucket_key, last_attempt_at, attempt_times) VALUES (?, ?, ?)`,
		bucketKey("password", "alice"), now, encodeAttempts([]int64{now - 1}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.limiter.BeginPassword(ctx, "alice", "192.0.2.16"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("inconsistent attempt-bucket metadata did not fail closed: %v", err)
	}
	var sourceBuckets int
	if err := fixture.db.QueryRowContext(ctx,
		"SELECT count(*) FROM registry_auth_attempt_buckets WHERE bucket_key = ?", bucketKey("source", "192.0.2.16")).Scan(&sourceBuckets); err != nil {
		t.Fatal(err)
	}
	if sourceBuckets != 0 {
		t.Fatal("failed attempt transaction left partial source-bucket state")
	}
}
