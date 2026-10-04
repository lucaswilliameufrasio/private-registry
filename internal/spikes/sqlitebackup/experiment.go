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

	"filippo.io/age"
)

type Report struct {
	Driver          string        `json:"driver"`
	SQLiteVersion   string        `json:"sqlite_version"`
	Progress        Progress      `json:"snapshot"`
	WritesDuring    int           `json:"writes_between_backup_steps"`
	RestoredRows    int           `json:"restored_rows"`
	SnapshotSHA256  string        `json:"snapshot_sha256"`
	RestoredSHA256  string        `json:"restored_sha256"`
	Integrity       string        `json:"integrity"`
	Duration        time.Duration `json:"duration_ns"`
	RemoteValidated bool          `json:"remote_validated"`
}

// Experiment owns a new, synthetic database beneath directory. It proves
// online copying across externally committed writes and a local age roundtrip,
// not a production backup, S3 upload, or remote restore validation.
func Experiment(ctx context.Context, directory string) (report Report, err error) {
	start := time.Now()
	report.Driver = "modernc.org/sqlite v1.60.1"
	source := filepath.Join(directory, "source.db")
	reserved, err := os.OpenFile(source, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return report, err
	}
	if err := reserved.Close(); err != nil {
		return report, err
	}
	dsn, err := DSN(source)
	if err != nil {
		return report, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return report, err
	}
	db.SetMaxOpenConns(4)
	defer func() { err = errors.Join(err, db.Close()) }()
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE owners (id INTEGER PRIMARY KEY);
		CREATE TABLE entries (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES owners(id), payload BLOB NOT NULL);
		INSERT INTO owners VALUES (1);
		WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM numbers WHERE n < 128)
		INSERT INTO entries(owner_id, payload) SELECT 1, zeroblob(2048) FROM numbers;
	`); err != nil {
		return report, fmt.Errorf("seed experiment: %w", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&report.SQLiteVersion); err != nil {
		return report, err
	}

	// The writer runs on another goroutine/connection while the backup's Raw
	// connection remains borrowed. Handshakes make overlap reproducible rather
	// than hoping a short backup intersects a timing-dependent write loop.
	requests := make(chan chan error)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for reply := range requests {
			_, err := db.ExecContext(ctx, "INSERT INTO entries(owner_id, payload) VALUES(1, zeroblob(2048))")
			reply <- err
		}
	}()
	defer func() { close(requests); <-done }()
	snapshot := filepath.Join(directory, "snapshot.db")
	report.Progress, err = Snapshot(ctx, db, snapshot, Options{
		PagesPerStep: 8,
		AfterStep: func(progress Progress) error {
			if progress.Remaining == 0 || report.WritesDuring >= 3 {
				return nil
			}
			reply := make(chan error, 1)
			select {
			case requests <- reply:
			case <-ctx.Done():
				return ctx.Err()
			}
			select {
			case err := <-reply:
				if err != nil {
					return err
				}
				report.WritesDuring++
			case <-ctx.Done():
				return ctx.Err()
			}
			var count int
			return db.QueryRowContext(ctx, "SELECT COUNT(*) FROM entries").Scan(&count)
		},
	})
	if err != nil {
		return report, err
	}
	if report.WritesDuring != 3 || report.Progress.Steps <= 1 {
		return report, errors.New("experiment did not observe writes during incremental backup")
	}
	report.SnapshotSHA256, err = Digest(snapshot)
	if err != nil {
		return report, err
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return report, err
	}
	ciphertext := filepath.Join(directory, "snapshot.db.age")
	if err := Encrypt(ctx, snapshot, ciphertext, identity.Recipient()); err != nil {
		return report, err
	}
	// The validation must read ciphertext, not reuse the original snapshot.
	if err := os.Remove(snapshot); err != nil {
		return report, err
	}
	restored := filepath.Join(directory, "restored.db")
	if err := Decrypt(ctx, ciphertext, restored, identity); err != nil {
		return report, err
	}
	report.RestoredSHA256, err = Digest(restored)
	if err != nil {
		return report, err
	}
	if report.RestoredSHA256 != report.SnapshotSHA256 {
		return report, errors.New("restored bytes differ from snapshot")
	}
	u := url.URL{Scheme: "file", Path: restored}
	u.RawQuery = "mode=ro"
	recovery, err := sql.Open("sqlite", u.String())
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, recovery.Close()) }()
	if err := recovery.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&report.Integrity); err != nil {
		return report, err
	}
	if report.Integrity != "ok" {
		return report, fmt.Errorf("integrity check: %s", report.Integrity)
	}
	violations, err := recovery.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return report, err
	}
	if violations.Next() {
		return report, errors.Join(errors.New("foreign key violation after restore"), violations.Close())
	}
	if err := errors.Join(violations.Err(), violations.Close()); err != nil {
		return report, err
	}
	if err := recovery.QueryRowContext(ctx, "SELECT COUNT(*) FROM entries").Scan(&report.RestoredRows); err != nil {
		return report, err
	}
	if report.RestoredRows != 128+report.WritesDuring {
		return report, errors.New("restored snapshot missed committed writes")
	}
	report.Duration = time.Since(start)
	return report, nil
}
