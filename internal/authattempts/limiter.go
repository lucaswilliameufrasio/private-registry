package authattempts

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"private-registry/internal/config"
)

const (
	windowDuration           = 15 * time.Minute
	accountLimit             = 5
	sourceLimit              = 20
	maxBuckets               = 50000
	personalTokenSourceLimit = 20
)

var (
	ErrUnavailable   = errors.New("authentication attempt limiter is unavailable")
	ErrRateLimited   = errors.New("authentication attempts are temporarily limited")
	ErrInvalidSource = errors.New("client network address is invalid")
	ErrCapacity      = errors.New("authentication attempt state is at capacity")
)

type Limiter struct {
	db             *sql.DB
	driver         config.DatabaseDriver
	now            func() time.Time
	bucketCapacity int
}

// BeginPersonalToken bounds repeated bearer failures separately from password
// and MFA source buckets. Successful bearer validation clears this bucket.
func (l *Limiter) BeginPersonalToken(ctx context.Context, source string) (time.Duration, error) {
	canonicalSource, err := normalizeSource(source)
	if err != nil {
		return 0, err
	}
	return l.begin(ctx, []bucket{{key: bucketKey("personal-token-source", canonicalSource), limit: personalTokenSourceLimit}})
}

func (l *Limiter) CompletePersonalToken(ctx context.Context, source string) error {
	canonicalSource, err := normalizeSource(source)
	if err != nil {
		return err
	}
	return l.reset(ctx, bucketKey("personal-token-source", canonicalSource))
}

type bucket struct {
	key   string
	limit int
}

func New(db *sql.DB, driver config.DatabaseDriver) (*Limiter, error) {
	if db == nil || (driver != config.SQLite && driver != config.Postgres) {
		return nil, ErrUnavailable
	}
	return &Limiter{db: db, driver: driver, now: time.Now, bucketCapacity: maxBuckets}, nil
}

func (l *Limiter) BeginPassword(ctx context.Context, loginName, source string) (time.Duration, error) {
	canonicalSource, err := normalizeSource(source)
	if err != nil {
		return 0, err
	}
	if len(loginName) > 63 {
		loginName = "<invalid-login>"
	}
	return l.begin(ctx, []bucket{
		{key: bucketKey("source", canonicalSource), limit: sourceLimit},
		{key: bucketKey("password", loginName), limit: accountLimit},
	})
}

func (l *Limiter) CompletePassword(ctx context.Context, loginName string) error {
	if len(loginName) > 63 {
		loginName = "<invalid-login>"
	}
	return l.reset(ctx, bucketKey("password", loginName))
}

func (l *Limiter) BeginMFA(ctx context.Context, userID, source string) (time.Duration, error) {
	canonicalSource, err := normalizeSource(source)
	if err != nil {
		return 0, err
	}
	if len(userID) > 64 {
		return 0, ErrUnavailable
	}
	return l.begin(ctx, []bucket{
		{key: bucketKey("source", canonicalSource), limit: sourceLimit},
		{key: bucketKey("mfa", userID), limit: accountLimit},
	})
}

func (l *Limiter) CompleteMFA(ctx context.Context, userID string) error {
	if len(userID) > 64 {
		return ErrUnavailable
	}
	return l.reset(ctx, bucketKey("mfa", userID))
}

func (l *Limiter) begin(ctx context.Context, buckets []bucket) (retryAfter time.Duration, retErr error) {
	if err := l.validate(ctx); err != nil {
		return 0, err
	}
	now := l.now().UTC().Unix()
	cutoff := now - int64(windowDuration/time.Second)
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, ErrUnavailable
	}
	defer rollback(tx, &retErr)
	if err := lockCapacity(ctx, tx, l.driver); err != nil {
		return 0, ErrUnavailable
	}
	deleteExpired := "DELETE FROM registry_auth_attempt_buckets WHERE last_attempt_at <= " + bind(l.driver, 1)
	if _, err := tx.ExecContext(ctx, deleteExpired, cutoff); err != nil {
		return 0, ErrUnavailable
	}
	for _, current := range buckets {
		attempts, exists, err := readBucket(ctx, tx, l.driver, current.key)
		if err != nil {
			return 0, ErrUnavailable
		}
		if exists && (attempts[len(attempts)-1] > now) {
			return 0, ErrUnavailable
		}
		activeAttempts := make([]int64, 0, len(attempts)+1)
		for _, attemptedAt := range attempts {
			if attemptedAt > cutoff {
				activeAttempts = append(activeAttempts, attemptedAt)
			}
		}
		sort.Slice(activeAttempts, func(left, right int) bool {
			return activeAttempts[left] < activeAttempts[right]
		})
		if !exists {
			count, err := bucketCount(ctx, tx)
			if err != nil {
				return 0, ErrUnavailable
			}
			if count >= l.bucketCapacity {
				if err := tx.Commit(); err != nil {
					return 0, ErrUnavailable
				}
				return 0, ErrCapacity
			}
			activeAttempts = append(activeAttempts, now)
			sort.Slice(activeAttempts, func(left, right int) bool {
				return activeAttempts[left] < activeAttempts[right]
			})
			if err := insertBucket(ctx, tx, l.driver, current.key, activeAttempts); err != nil {
				return 0, ErrUnavailable
			}
			continue
		}
		if len(activeAttempts) >= current.limit {
			if err := updateBucket(ctx, tx, l.driver, current.key, activeAttempts); err != nil {
				return 0, ErrUnavailable
			}
			retryAfter = time.Duration(activeAttempts[0]+int64(windowDuration/time.Second)-now) * time.Second
			if retryAfter < time.Second {
				retryAfter = time.Second
			}
			if err := tx.Commit(); err != nil {
				return 0, ErrUnavailable
			}
			return retryAfter, ErrRateLimited
		}
		activeAttempts = append(activeAttempts, now)
		sort.Slice(activeAttempts, func(left, right int) bool {
			return activeAttempts[left] < activeAttempts[right]
		})
		if err := updateBucket(ctx, tx, l.driver, current.key, activeAttempts); err != nil {
			return 0, ErrUnavailable
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, ErrUnavailable
	}
	return 0, nil
}

func (l *Limiter) reset(ctx context.Context, key string) (retErr error) {
	if err := l.validate(ctx); err != nil {
		return err
	}
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer rollback(tx, &retErr)
	if err := lockCapacity(ctx, tx, l.driver); err != nil {
		return ErrUnavailable
	}
	query := "DELETE FROM registry_auth_attempt_buckets WHERE bucket_key = " + bind(l.driver, 1)
	if _, err := tx.ExecContext(ctx, query, key); err != nil {
		return ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (l *Limiter) validate(ctx context.Context) error {
	if l == nil || l.db == nil || l.now == nil || (l.driver != config.SQLite && l.driver != config.Postgres) || ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func lockCapacity(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver) error {
	if driver == config.Postgres {
		var singletonID int
		return tx.QueryRowContext(ctx,
			"SELECT singleton_id FROM registry_installation WHERE singleton_id = 1 FOR UPDATE").Scan(&singletonID)
	}
	result, err := tx.ExecContext(ctx,
		"UPDATE registry_installation SET created_at = created_at WHERE singleton_id = 1")
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected != 1 {
		return errors.New("installation lock row is unavailable")
	}
	return nil
}

func readBucket(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, key string) ([]int64, bool, error) {
	query := "SELECT last_attempt_at, attempt_times FROM registry_auth_attempt_buckets WHERE bucket_key = " + bind(driver, 1)
	var lastAttemptAt int64
	var encodedAttempts []byte
	err := tx.QueryRowContext(ctx, query, key).Scan(&lastAttemptAt, &encodedAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	attempts, err := decodeAttempts(encodedAttempts)
	if err != nil {
		return nil, false, err
	}
	if len(attempts) == 0 || attempts[len(attempts)-1] != lastAttemptAt {
		return nil, false, ErrUnavailable
	}
	return attempts, true, nil
}

func bucketCount(ctx context.Context, tx *sql.Tx) (int, error) {
	var count int
	err := tx.QueryRowContext(ctx, "SELECT count(*) FROM registry_auth_attempt_buckets").Scan(&count)
	return count, err
}

func insertBucket(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, key string, attempts []int64) error {
	if len(attempts) == 0 {
		return ErrUnavailable
	}
	query := `INSERT INTO registry_auth_attempt_buckets (bucket_key, last_attempt_at, attempt_times)
		VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, ` + bind(driver, 3) + `)`
	_, err := tx.ExecContext(ctx, query, key, attempts[len(attempts)-1], encodeAttempts(attempts))
	return err
}

func updateBucket(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, key string, attempts []int64) error {
	if len(attempts) == 0 {
		query := "DELETE FROM registry_auth_attempt_buckets WHERE bucket_key = " + bind(driver, 1)
		_, err := tx.ExecContext(ctx, query, key)
		return err
	}
	query := `UPDATE registry_auth_attempt_buckets SET last_attempt_at = ` + bind(driver, 1) +
		`, attempt_times = ` + bind(driver, 2) + ` WHERE bucket_key = ` + bind(driver, 3)
	_, err := tx.ExecContext(ctx, query, attempts[len(attempts)-1], encodeAttempts(attempts), key)
	return err
}

func encodeAttempts(attempts []int64) []byte {
	encoded := make([]byte, len(attempts)*8)
	for index, attemptedAt := range attempts {
		binary.BigEndian.PutUint64(encoded[index*8:(index+1)*8], uint64(attemptedAt))
	}
	return encoded
}

func decodeAttempts(encoded []byte) ([]int64, error) {
	if len(encoded) == 0 || len(encoded)%8 != 0 || len(encoded) > sourceLimit*8 {
		return nil, ErrUnavailable
	}
	attempts := make([]int64, len(encoded)/8)
	for index := range attempts {
		timestamp := binary.BigEndian.Uint64(encoded[index*8 : (index+1)*8])
		if timestamp > uint64(^uint64(0)>>1) {
			return nil, ErrUnavailable
		}
		attempts[index] = int64(timestamp)
		if index > 0 && attempts[index] < attempts[index-1] {
			return nil, ErrUnavailable
		}
	}
	return attempts, nil
}

func normalizeSource(source string) (string, error) {
	source = strings.TrimSpace(source)
	if source == "" || len(source) > 128 {
		return "", ErrInvalidSource
	}
	host := source
	if parsedHost, _, err := net.SplitHostPort(source); err == nil {
		host = parsedHost
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "", ErrInvalidSource
	}
	return address.WithZone("").Unmap().String(), nil
}

func bucketKey(kind, identity string) string {
	digest := sha256.Sum256([]byte(kind + "\x00" + identity))
	return hex.EncodeToString(digest[:])
}

func rollback(tx *sql.Tx, retErr *error) {
	if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
		*retErr = errors.Join(*retErr, ErrUnavailable)
	}
}

func bind(driver config.DatabaseDriver, position int) string {
	if driver == config.Postgres {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}
