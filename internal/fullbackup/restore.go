package fullbackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"private-registry/internal/config"
	"private-registry/internal/storage"
)

// VerifyReport is the outcome of a full verification.
type VerifyReport struct {
	ID            string
	Objects       int
	DatabaseBytes int64
}

// Verify downloads and decrypts one backup with the operator's identity,
// checks the database digest and integrity, checks that the database names
// only objects the manifest lists, and decrypts and checks every object. It
// never touches the installation.
func Verify(ctx context.Context, bucket Bucket, identity age.Identity, id, staging, pgRestore string) (VerifyReport, error) {
	manifest, plaintextPath, cleanup, err := fetchDatabase(ctx, bucket, identity, id, staging)
	if err != nil {
		return VerifyReport{}, err
	}
	defer cleanup()
	listed := make(map[storage.ObjectKey]int64, len(manifest.Objects))
	for _, object := range manifest.Objects {
		key, _ := storage.NewObjectKey(object.WorkspaceID, object.SHA256)
		listed[key] = object.Size
	}
	switch config.DatabaseDriver(manifest.Driver) {
	case config.SQLite:
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(plaintextPath)+"?mode=ro&immutable=1")
		if err != nil {
			return VerifyReport{}, errors.New("backed-up database could not be opened")
		}
		defer db.Close()
		for _, check := range []string{"PRAGMA integrity_check", "PRAGMA foreign_key_check"} {
			rows, err := db.QueryContext(ctx, check)
			if err != nil {
				return VerifyReport{}, fmt.Errorf("%s could not run on the backup", check)
			}
			problems := 0
			for rows.Next() {
				var first any
				columns, _ := rows.Columns()
				values := make([]any, len(columns))
				for index := range values {
					values[index] = &first
				}
				_ = rows.Scan(values...)
				if check == "PRAGMA integrity_check" {
					if text, ok := first.(string); ok && text == "ok" {
						continue
					}
				}
				problems++
			}
			_ = rows.Close()
			if problems > 0 {
				return VerifyReport{}, fmt.Errorf("backed-up database failed %s", check)
			}
		}
		installation, referenced, err := readInstallation(ctx, db, config.SQLite)
		if err != nil {
			return VerifyReport{}, err
		}
		if installation != manifest.InstallationID {
			return VerifyReport{}, errors.New("backed-up database belongs to another installation than its manifest says")
		}
		for key := range referenced {
			if _, ok := listed[key]; !ok {
				return VerifyReport{}, fmt.Errorf("backed-up database references object %s/%s that the backup does not contain", key.WorkspaceID, key.SHA256)
			}
		}
	case config.Postgres:
		if pgRestore == "" {
			pgRestore = "pg_restore"
		}
		// Reading the archive's table of contents checks its structure
		// without a server; restoring it is the restore drill's job.
		if err := postgresTool(ctx, pgRestore, "", io.Discard, nil, "--list", plaintextPath); err != nil {
			return VerifyReport{}, err
		}
	default:
		return VerifyReport{}, errors.New("backup manifest names an unknown database driver")
	}
	for key, size := range listed {
		if err := verifyObject(ctx, bucket, identity, key, size, io.Discard); err != nil {
			return VerifyReport{}, err
		}
	}
	return VerifyReport{ID: manifest.ID, Objects: len(listed), DatabaseBytes: manifest.DatabaseBytes}, nil
}

// fetchDatabase downloads, decrypts and checks the database dump of id (the
// newest complete backup when id is empty) into a private staging file.
func fetchDatabase(ctx context.Context, bucket Bucket, identity age.Identity, id, staging string) (Manifest, string, func(), error) {
	if identity == nil || staging == "" {
		return Manifest{}, "", nil, errors.New("backup identity and staging directory are required")
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return Manifest{}, "", nil, errors.New("staging directory could not be created")
	}
	if info, err := os.Lstat(staging); err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return Manifest{}, "", nil, errors.New("staging directory must be private")
	}
	if id == "" {
		ids, err := ListBackups(ctx, bucket)
		if err != nil {
			return Manifest{}, "", nil, err
		}
		if len(ids) == 0 {
			return Manifest{}, "", nil, errors.New("the backup bucket holds no complete backup")
		}
		id = ids[0]
	}
	manifest, err := readManifest(ctx, bucket, id)
	if err != nil {
		return Manifest{}, "", nil, err
	}
	encrypted, err := os.CreateTemp(staging, "database-*.age")
	if err != nil {
		return Manifest{}, "", nil, errors.New("staging file could not be created")
	}
	defer os.Remove(encrypted.Name())
	if err := bucket.get(ctx, bucket.key("backups", id, "database.age"), maxDumpBytes+(maxDumpBytes>>4), encrypted); err != nil {
		_ = encrypted.Close()
		return Manifest{}, "", nil, fmt.Errorf("encrypted database could not be downloaded: %w", err)
	}
	if _, err := encrypted.Seek(0, io.SeekStart); err != nil {
		_ = encrypted.Close()
		return Manifest{}, "", nil, errors.New("staging file could not be rewound")
	}
	plaintext, err := os.CreateTemp(staging, "database-*.dump")
	if err != nil {
		_ = encrypted.Close()
		return Manifest{}, "", nil, errors.New("staging file could not be created")
	}
	cleanup := func() { removeDatabaseFiles(plaintext.Name()) }
	// age authenticates every chunk; the digest then ties the bytes to the
	// manifest. Nothing reads the dump before both checks pass.
	reader, err := age.Decrypt(encrypted, identity)
	if err != nil {
		_ = encrypted.Close()
		_ = plaintext.Close()
		cleanup()
		return Manifest{}, "", nil, errors.New("database dump could not be decrypted with this identity")
	}
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(plaintext, hash), io.LimitReader(reader, maxDumpBytes+1))
	closeErr := errors.Join(encrypted.Close(), plaintext.Close())
	if copyErr != nil || closeErr != nil {
		cleanup()
		return Manifest{}, "", nil, errors.New("database dump failed decryption or could not be staged")
	}
	if size != manifest.DatabaseBytes || hex.EncodeToString(hash.Sum(nil)) != manifest.DatabaseSHA256 {
		cleanup()
		return Manifest{}, "", nil, errors.New("database dump does not match its manifest")
	}
	return manifest, plaintext.Name(), cleanup, nil
}

func verifyObject(ctx context.Context, bucket Bucket, identity age.Identity, key storage.ObjectKey, size int64, destination io.Writer) error {
	var encrypted bytes.Buffer
	if err := bucket.get(ctx, bucket.key("objects", key.WorkspaceID, key.SHA256+".age"), size+size/8+4096, &encrypted); err != nil {
		return fmt.Errorf("backup object %s/%s could not be downloaded: %w", key.WorkspaceID, key.SHA256, err)
	}
	reader, err := age.Decrypt(&encrypted, identity)
	if err != nil {
		return fmt.Errorf("backup object %s/%s could not be decrypted", key.WorkspaceID, key.SHA256)
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(reader, size+1))
	if err != nil || written != size || hex.EncodeToString(hash.Sum(nil)) != key.SHA256 {
		return fmt.Errorf("backup object %s/%s failed verification", key.WorkspaceID, key.SHA256)
	}
	return nil
}

// RestoreOptions configures a restore onto an empty installation.
type RestoreOptions struct {
	Bucket    Bucket
	Identity  age.Identity
	ID        string
	Staging   string
	Driver    config.DatabaseDriver
	SQLite    string // destination path; must not exist
	DB        *sql.DB
	DSN       string
	PgRestore string
	Store     storage.Driver
}

type RestoreReport struct {
	ID              string
	ObjectsRestored int
}

// Restore copies every object of the backup into the configured store, then
// restores the database. Objects come first so the database never names an
// object that is missing. The target database must be empty and the target
// SQLite path absent: nothing is overwritten.
func Restore(ctx context.Context, options RestoreOptions) (RestoreReport, error) {
	if options.Store == nil {
		return RestoreReport{}, errors.New("restore needs the configured object store")
	}
	manifest, plaintextPath, cleanup, err := fetchDatabase(ctx, options.Bucket, options.Identity, options.ID, options.Staging)
	if err != nil {
		return RestoreReport{}, err
	}
	defer cleanup()
	if config.DatabaseDriver(manifest.Driver) != options.Driver {
		return RestoreReport{}, fmt.Errorf("backup holds a %s database; the installation is configured for %s", manifest.Driver, options.Driver)
	}
	switch options.Driver {
	case config.SQLite:
		if _, err := os.Lstat(options.SQLite); err == nil {
			return RestoreReport{}, errors.New("a database already exists at the configured path; restore-backup never overwrites one")
		}
	case config.Postgres:
		if options.DB == nil {
			return RestoreReport{}, errors.New("restore needs a connection to the empty target database")
		}
		var tables int
		if err := options.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema()`).Scan(&tables); err != nil {
			return RestoreReport{}, errors.New("target database could not be inspected")
		}
		if tables != 0 {
			return RestoreReport{}, errors.New("target PostgreSQL database is not empty; restore-backup never overwrites data")
		}
	}
	report := RestoreReport{ID: manifest.ID}
	for _, object := range manifest.Objects {
		key, _ := storage.NewObjectKey(object.WorkspaceID, object.SHA256)
		var plaintext bytes.Buffer
		if err := verifyObject(ctx, options.Bucket, options.Identity, key, object.Size, &plaintext); err != nil {
			return report, err
		}
		written, err := options.Store.Put(ctx, key.WorkspaceID, &plaintext, object.Size)
		if err != nil || written.Key != key {
			return report, fmt.Errorf("object %s/%s could not be restored: %w", key.WorkspaceID, key.SHA256, err)
		}
		report.ObjectsRestored++
	}
	switch options.Driver {
	case config.SQLite:
		directory := filepath.Dir(options.SQLite)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return report, errors.New("database directory could not be created")
		}
		// The verified file is linked into place, so a crash cannot leave a
		// partial database at the configured path.
		stage := filepath.Join(directory, ".restore-"+manifest.ID+".sqlite")
		if err := copyFile(plaintextPath, stage); err != nil {
			return report, err
		}
		defer os.Remove(stage)
		if err := os.Link(stage, options.SQLite); err != nil {
			return report, errors.New("restored database could not be put in place; nothing was overwritten")
		}
	case config.Postgres:
		if options.PgRestore == "" {
			options.PgRestore = "pg_restore"
		}
		if err := postgresMajor(ctx, options.DB, options.PgRestore); err != nil {
			return report, err
		}
		dump, err := os.Open(plaintextPath)
		if err != nil {
			return report, errors.New("database dump could not be read")
		}
		defer dump.Close()
		name, err := postgresDatabaseName(options.DSN)
		if err != nil {
			return report, err
		}
		if err := postgresTool(ctx, options.PgRestore, options.DSN, io.Discard, dump, "--no-owner", "--no-acl", "--single-transaction", "--exit-on-error", "--dbname="+name); err != nil {
			return report, err
		}
	}
	return report, nil
}

func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return errors.New("database dump could not be read")
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("restored database could not be staged")
	}
	_, copyErr := io.Copy(output, input)
	if err := errors.Join(copyErr, output.Sync(), output.Close()); err != nil {
		_ = os.Remove(destination)
		return errors.New("restored database could not be staged")
	}
	return nil
}
