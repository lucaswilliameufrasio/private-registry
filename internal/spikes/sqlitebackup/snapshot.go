// Package sqlitebackup is an isolated phase-0 experiment, not a production
// backup service. It deliberately does not implement storage, pins, or jobs.
package sqlitebackup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"modernc.org/sqlite"
)

// Progress is the driver's most recent observation. Concurrent writes may
// restart the copy, so Remaining is not necessarily monotonically decreasing.
type Progress struct {
	Steps     int
	Pages     int
	Remaining int
}

type Options struct {
	PagesPerStep int32
	Pause        time.Duration
	// AfterStep is only an observation/test hook; it cannot approve a backup.
	AfterStep func(Progress) error
}

// DSN applies the experimental durability settings to every pooled connection.
func DSN(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	u := url.URL{Scheme: "file", Path: absolute}
	q := u.Query()
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "busy_timeout(100)")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Snapshot uses the actual sqlite3 online backup API through modernc's Raw
// connection. The caller must bound starvation with a context deadline.
// A destination is never overwritten; failed snapshots are discarded.
func Snapshot(ctx context.Context, db *sql.DB, destination string, options Options) (progress Progress, err error) {
	if db == nil {
		return progress, errors.New("source database is required")
	}
	if _, ok := ctx.Deadline(); !ok {
		return progress, errors.New("snapshot requires a context deadline")
	}
	if options.PagesPerStep <= 0 || options.Pause < 0 {
		return progress, errors.New("positive pages per step and nonnegative pause required")
	}
	if err := ctx.Err(); err != nil {
		return progress, err
	}
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return progress, fmt.Errorf("reserve snapshot: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, removeFile(destination))
		}
	}()
	if err = f.Close(); err != nil {
		return progress, err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return progress, err
	}
	defer func() { err = errors.Join(err, conn.Close()) }()

	err = conn.Raw(func(raw any) (rawErr error) {
		backuper, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("driver does not expose modernc online backup")
		}
		absolute, err := filepath.Abs(destination)
		if err != nil {
			return err
		}
		u := url.URL{Scheme: "file", Path: absolute}
		backup, err := backuper.NewBackup(u.String())
		if err != nil {
			return fmt.Errorf("initialize online backup: %w", err)
		}
		defer func() { rawErr = errors.Join(rawErr, backup.Finish()) }()
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			more, err := backup.Step(options.PagesPerStep)
			if err != nil {
				var sqliteErr *sqlite.Error
				if errors.As(err, &sqliteErr) && (sqliteErr.Code()&0xff == 5 || sqliteErr.Code()&0xff == 6) {
					if err := pause(ctx, 5*time.Millisecond); err != nil {
						return err
					}
					continue
				}
				return fmt.Errorf("copy backup pages: %w", err)
			}
			progress.Steps++
			progress.Pages = backup.PageCount()
			progress.Remaining = backup.Remaining()
			if options.AfterStep != nil {
				if err := options.AfterStep(progress); err != nil {
					return err
				}
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if !more {
				return nil
			}
			if err := pause(ctx, options.Pause); err != nil {
				return err
			}
		}
	})
	return progress, err
}

func pause(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func removeFile(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
