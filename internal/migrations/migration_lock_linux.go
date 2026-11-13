//go:build linux

package migrations

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pressly/goose/v3/lock"
	"private-registry/internal/config"
)

const postgresMigrationLockID int64 = 0x5052474d49475231

func acquireMigrationLock(
	ctx context.Context,
	db *sql.DB,
	driver config.DatabaseDriver,
	databaseDSN string,
) (func() error, error) {
	if driver == config.Postgres {
		locker, err := lock.NewPostgresSessionLocker(
			lock.WithLockID(postgresMigrationLockID),
			lock.WithLockTimeout(1, 60),
			lock.WithUnlockTimeout(1, 15),
		)
		if err != nil {
			return nil, errors.New("PostgreSQL migration lock could not be initialized")
		}
		connection, err := db.Conn(ctx)
		if err != nil {
			return nil, errors.New("PostgreSQL migration lock connection could not be opened")
		}
		if err := locker.SessionLock(ctx, connection); err != nil {
			_ = connection.Close()
			return nil, errors.Join(errors.New("PostgreSQL migration lock could not be acquired"), err)
		}
		return func() error {
			unlockContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			unlockErr := locker.SessionUnlock(unlockContext, connection)
			closeErr := connection.Close()
			if unlockErr != nil || closeErr != nil {
				return errors.New("PostgreSQL migration lock could not be released cleanly")
			}
			return nil
		}, nil
	}
	if driver != config.SQLite {
		return nil, errors.New("unsupported database migration lock")
	}
	return acquireSQLiteFileLock(ctx, databaseDSN)
}

func acquireSQLiteFileLock(ctx context.Context, databasePath string) (func() error, error) {
	if !filepath.IsAbs(databasePath) {
		return nil, errors.New("SQLite migration database path must be absolute")
	}
	directory := filepath.Dir(databasePath)
	directoryInfo, err := os.Stat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("SQLite migration directory must be private to its owner")
	}

	lockPath := databasePath + ".migrate.lock"
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errors.New("SQLite migration lock file could not be opened")
	}
	fileInfo, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(lockPath)
	if statErr != nil || pathErr != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm()&0o077 != 0 ||
		!pathInfo.Mode().IsRegular() || !os.SameFile(fileInfo, pathInfo) {
		_ = file.Close()
		return nil, errors.New("SQLite migration lock file must be a private regular file")
	}

	for {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return nil, err
		}
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() error {
				unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				closeErr := file.Close()
				if unlockErr != nil || closeErr != nil {
					return errors.New("SQLite migration lock could not be released cleanly")
				}
				return nil
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			_ = file.Close()
			return nil, errors.New("SQLite migration lock could not be acquired")
		}

		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
