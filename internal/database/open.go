package database

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
	"private-registry/internal/config"
)

func Open(ctx context.Context, cfg config.Config) (*sql.DB, error) {
	if ctx == nil {
		return nil, errors.New("database context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.DatabaseMaxOpenConns < 1 || cfg.DatabaseMaxOpenConns > 128 {
		return nil, errors.New("database max open connections must be between 1 and 128")
	}

	var db *sql.DB
	switch cfg.DatabaseDriver {
	case config.SQLite:
		if err := prepareSQLiteFile(cfg.DatabaseDSN); err != nil {
			return nil, err
		}
		dsn, err := sqliteDSN(cfg.DatabaseDSN)
		if err != nil {
			return nil, errors.New("SQLite database path is invalid")
		}
		db, err = sql.Open("sqlite", dsn)
		if err != nil {
			return nil, errors.New("SQLite database could not be opened")
		}
		db.SetMaxOpenConns(cfg.DatabaseMaxOpenConns)
		db.SetMaxIdleConns(cfg.DatabaseMaxOpenConns)
	case config.Postgres:
		pgxConfig, err := pgx.ParseConfig(cfg.DatabaseDSN)
		if err != nil {
			return nil, errors.New("PostgreSQL database DSN is invalid")
		}
		db = stdlib.OpenDB(*pgxConfig)
		db.SetMaxOpenConns(cfg.DatabaseMaxOpenConns)
		db.SetMaxIdleConns(cfg.DatabaseMaxOpenConns / 2)
		db.SetConnMaxIdleTime(5 * time.Minute)
		db.SetConnMaxLifetime(30 * time.Minute)
	default:
		return nil, errors.New("database driver must be sqlite or postgres")
	}

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, errors.New("database connection failed")
	}
	return db, nil
}

func prepareSQLiteFile(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("SQLite database path must be absolute")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("SQLite database directory could not be created")
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("SQLite database directory must be private to its owner")
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err == nil {
		if closeErr := file.Close(); closeErr != nil {
			return errors.New("SQLite database file could not be initialized")
		}
		return nil
	}
	if !errors.Is(err, os.ErrExist) {
		return errors.New("SQLite database file could not be initialized")
	}

	fileInfo, err := os.Lstat(path)
	if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("existing SQLite database file must be private and regular")
	}
	return nil
}

func sqliteDSN(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}
	query := u.Query()
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "foreign_keys(ON)")
	query.Add("_pragma", "synchronous(FULL)")
	query.Add("_pragma", "busy_timeout(5000)")
	u.RawQuery = query.Encode()
	return u.String(), nil
}
