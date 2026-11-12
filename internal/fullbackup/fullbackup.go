// Package fullbackup writes, verifies and restores complete installation
// backups to a dedicated S3-compatible bucket: the database (SQLite through
// the Online Backup API, PostgreSQL through pg_dump on an exported snapshot)
// and every object the backed-up database references. Everything stored in
// the bucket is age-encrypted to a recipient whose identity the installation
// never holds, so the server cannot read its own backups and a leaked bucket
// exposes no package content.
//
// Layout under the configured prefix:
//
//	objects/<workspace>/<sha256>.age      immutable, shared by every backup
//	backups/<id>/database.age             encrypted dump
//	backups/<id>/manifest.json            written last; a backup without it is incomplete
//
// The master key, secret files and configuration are not included.
package fullbackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"crypto/rand"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"modernc.org/sqlite"
	"private-registry/internal/config"
	"private-registry/internal/objectmaint"
	"private-registry/internal/storage"
)

var randReader = rand.Reader

const (
	manifestVersion  = 1
	maxManifestBytes = 256 << 20
	maxDumpBytes     = 64 << 30
)

var backupIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)

// Bucket is the narrow S3 surface the package uses.
type Bucket struct {
	Client *s3.Client
	Name   string
	Prefix string
}

func (b Bucket) key(parts ...string) string {
	path := strings.Join(parts, "/")
	if b.Prefix == "" {
		return path
	}
	return b.Prefix + "/" + path
}

func (b Bucket) put(ctx context.Context, key string, body io.ReadSeeker, size int64, exclusive bool) error {
	input := &s3.PutObjectInput{Bucket: aws.String(b.Name), Key: aws.String(key), Body: body, ContentLength: aws.Int64(size)}
	if exclusive {
		input.IfNoneMatch = aws.String("*")
	}
	_, err := b.Client.PutObject(ctx, input)
	return err
}

func (b Bucket) get(ctx context.Context, key string, limit int64, destination io.Writer) error {
	output, err := b.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(b.Name), Key: aws.String(key)})
	if err != nil {
		return err
	}
	defer output.Body.Close()
	written, err := io.Copy(destination, io.LimitReader(output.Body, limit+1))
	if err != nil {
		return err
	}
	if written > limit {
		return errors.New("backup object exceeds its size limit")
	}
	return nil
}

// list returns key -> size below prefix.
func (b Bucket) list(ctx context.Context, prefix string) (map[string]int64, error) {
	found := make(map[string]int64)
	paginator := s3.NewListObjectsV2Paginator(b.Client, &s3.ListObjectsV2Input{Bucket: aws.String(b.Name), Prefix: aws.String(b.key(prefix))})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, object := range page.Contents {
			if object.Key != nil && object.Size != nil {
				found[*object.Key] = *object.Size
			}
		}
	}
	return found, nil
}

func (b Bucket) delete(ctx context.Context, key string) error {
	_, err := b.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(b.Name), Key: aws.String(key)})
	return err
}

// Manifest describes one complete backup. It contains identifiers and
// digests, never package content or credentials.
type Manifest struct {
	Version        int              `json:"version"`
	ID             string           `json:"id"`
	InstallationID string           `json:"installation_id"`
	CreatedAt      time.Time        `json:"created_at"`
	Driver         string           `json:"database_driver"`
	SchemaVersion  int              `json:"schema_version"`
	DatabaseSHA256 string           `json:"database_sha256"`
	DatabaseBytes  int64            `json:"database_bytes"`
	Objects        []ManifestObject `json:"objects"`
}

type ManifestObject struct {
	WorkspaceID string `json:"workspace_id"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
}

// Options configures one backup run.
type Options struct {
	DB        *sql.DB
	Driver    config.DatabaseDriver
	DSN       string
	Store     storage.Driver
	Bucket    Bucket
	Recipient age.Recipient
	// PgDump is the pg_dump executable; its major version must match the
	// server's.
	PgDump  string
	Staging string
	Retain  int
	Now     time.Time
}

type Report struct {
	ID              string
	Objects         int
	ObjectsUploaded int
	BytesUploaded   int64
	DatabaseBytes   int64
	Removed         []string
}

// Run creates one backup and then applies retention.
func Run(ctx context.Context, options Options) (Report, error) {
	if options.DB == nil || options.Store == nil || options.Bucket.Client == nil || options.Recipient == nil || options.Retain < 1 || options.Staging == "" {
		return Report{}, errors.New("backup options are invalid")
	}
	if err := os.MkdirAll(options.Staging, 0o700); err != nil {
		return Report{}, errors.New("backup staging directory could not be created")
	}
	if info, err := os.Lstat(options.Staging); err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return Report{}, errors.New("backup staging directory must be private")
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	var suffix [4]byte
	if _, err := io.ReadFull(randReader, suffix[:]); err != nil {
		return Report{}, errors.New("backup identity could not be created")
	}
	manifest := Manifest{Version: manifestVersion, ID: now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(suffix[:]), CreatedAt: now.UTC(), Driver: string(options.Driver), SchemaVersion: objectmaint.KnownSchemaVersion}
	plaintext, err := os.CreateTemp(options.Staging, "database-*.dump")
	if err != nil {
		return Report{}, errors.New("database staging file could not be created")
	}
	plaintextPath := plaintext.Name()
	_ = plaintext.Close()
	defer removeDatabaseFiles(plaintextPath)

	// The dump and the object list come from the same consistent view, so
	// every object the restored database names is in the backup.
	var referenced map[storage.ObjectKey]struct{}
	switch options.Driver {
	case config.SQLite:
		if err := os.Remove(plaintextPath); err != nil {
			return Report{}, errors.New("database staging file could not be prepared")
		}
		if err := sqliteOnlineBackup(ctx, options.DB, plaintextPath); err != nil {
			return Report{}, err
		}
		copyDB, err := sql.Open("sqlite", "file:"+filepath.ToSlash(plaintextPath)+"?mode=ro&immutable=1")
		if err != nil {
			return Report{}, errors.New("database copy could not be opened")
		}
		manifest.InstallationID, referenced, err = readInstallation(ctx, copyDB, config.SQLite)
		closeErr := copyDB.Close()
		if err != nil {
			return Report{}, err
		}
		if closeErr != nil {
			return Report{}, errors.New("database copy could not be closed")
		}
	case config.Postgres:
		var err error
		manifest.InstallationID, referenced, err = postgresDump(ctx, options.DB, options.DSN, options.PgDump, plaintextPath)
		if err != nil {
			return Report{}, err
		}
	default:
		return Report{}, errors.New("database driver is not supported")
	}

	digest, size, err := fileDigest(plaintextPath)
	if err != nil {
		return Report{}, err
	}
	manifest.DatabaseSHA256, manifest.DatabaseBytes = digest, size
	report := Report{ID: manifest.ID, DatabaseBytes: size}

	present, err := options.Bucket.list(ctx, "objects/")
	if err != nil {
		return Report{}, fmt.Errorf("backup objects could not be listed: %w", err)
	}
	keys := make([]storage.ObjectKey, 0, len(referenced))
	for key := range referenced {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].WorkspaceID != keys[j].WorkspaceID {
			return keys[i].WorkspaceID < keys[j].WorkspaceID
		}
		return keys[i].SHA256 < keys[j].SHA256
	})
	for _, key := range keys {
		objectSize, uploaded, err := backupObject(ctx, options, present, key)
		if err != nil {
			return Report{}, err
		}
		manifest.Objects = append(manifest.Objects, ManifestObject{WorkspaceID: key.WorkspaceID, SHA256: key.SHA256, Size: objectSize})
		if uploaded {
			report.ObjectsUploaded++
			report.BytesUploaded += objectSize
		}
	}
	report.Objects = len(manifest.Objects)

	encrypted, err := encryptFile(plaintextPath, options.Staging, options.Recipient)
	if err != nil {
		return Report{}, err
	}
	defer os.Remove(encrypted)
	if err := uploadFile(ctx, options.Bucket, options.Bucket.key("backups", manifest.ID, "database.age"), encrypted); err != nil {
		return Report{}, fmt.Errorf("encrypted database could not be uploaded: %w", err)
	}
	document, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Report{}, errors.New("backup manifest could not be encoded")
	}
	if err := options.Bucket.put(ctx, options.Bucket.key("backups", manifest.ID, "manifest.json"), bytes.NewReader(document), int64(len(document)), true); err != nil {
		return Report{}, fmt.Errorf("backup manifest could not be uploaded: %w", err)
	}
	removed, err := applyRetention(ctx, options.Bucket, options.Retain)
	report.Removed = removed
	if err != nil {
		return report, fmt.Errorf("backup %s completed but retention failed: %w", manifest.ID, err)
	}
	return report, nil
}

func readInstallation(ctx context.Context, db *sql.DB, driver config.DatabaseDriver) (string, map[storage.ObjectKey]struct{}, error) {
	var installation string
	if err := db.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&installation); err != nil {
		return "", nil, errors.New("installation identity could not be read")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", nil, errors.New("database copy could not be read")
	}
	defer func() { _ = tx.Rollback() }()
	referenced, err := objectmaint.RequiredObjectsTx(ctx, tx)
	if err != nil {
		return "", nil, err
	}
	return installation, referenced, nil
}

// backupObject uploads an object that the bucket does not hold yet, after
// verifying it against its digest. Present objects are trusted by size here
// and fully checked by Verify.
func backupObject(ctx context.Context, options Options, present map[string]int64, key storage.ObjectKey) (int64, bool, error) {
	reader, info, err := options.Store.Open(ctx, key)
	if err != nil {
		return 0, false, fmt.Errorf("object %s/%s is referenced but could not be read or failed verification: %w", key.WorkspaceID, key.SHA256, err)
	}
	defer reader.Close()
	remote := options.Bucket.key("objects", key.WorkspaceID, key.SHA256+".age")
	if _, exists := present[remote]; exists {
		return info.Size, false, nil
	}
	stage, err := os.CreateTemp(options.Staging, "object-*.age")
	if err != nil {
		return 0, false, errors.New("object staging file could not be created")
	}
	defer os.Remove(stage.Name())
	sealed, err := age.Encrypt(stage, options.Recipient)
	if err != nil {
		_ = stage.Close()
		return 0, false, errors.New("object could not be encrypted")
	}
	if _, err := io.Copy(sealed, reader); err != nil {
		_ = stage.Close()
		return 0, false, errors.New("object could not be encrypted")
	}
	if err := errors.Join(sealed.Close(), stage.Close()); err != nil {
		return 0, false, errors.New("object could not be encrypted")
	}
	if err := uploadFile(ctx, options.Bucket, remote, stage.Name()); err != nil {
		return 0, false, fmt.Errorf("object %s/%s could not be uploaded: %w", key.WorkspaceID, key.SHA256, err)
	}
	return info.Size, true, nil
}

func uploadFile(ctx context.Context, bucket Bucket, key, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	return bucket.put(ctx, key, file, info.Size(), false)
}

func encryptFile(path, staging string, recipient age.Recipient) (string, error) {
	input, err := os.Open(path)
	if err != nil {
		return "", errors.New("database dump could not be read")
	}
	defer input.Close()
	output, err := os.CreateTemp(staging, "database-*.age")
	if err != nil {
		return "", errors.New("encrypted dump could not be created")
	}
	sealed, err := age.Encrypt(output, recipient)
	if err == nil {
		_, err = io.Copy(sealed, input)
		err = errors.Join(err, sealed.Close())
	}
	err = errors.Join(err, output.Sync(), output.Close())
	if err != nil {
		_ = os.Remove(output.Name())
		return "", errors.New("database dump could not be encrypted")
	}
	return output.Name(), nil
}

func fileDigest(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, errors.New("database dump could not be read")
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, errors.New("database dump could not be read")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func sqliteOnlineBackup(ctx context.Context, db *sql.DB, destination string) (err error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return errors.New("database connection for backup could not be opened")
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	return conn.Raw(func(raw any) (rawErr error) {
		backuper, ok := raw.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("SQLite driver does not expose the online backup API")
		}
		target := url.URL{Scheme: "file", Path: destination}
		backup, err := backuper.NewBackup(target.String())
		if err != nil {
			return errors.New("SQLite online backup could not start")
		}
		defer func() { rawErr = errors.Join(rawErr, backup.Finish()) }()
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			more, err := backup.Step(256)
			if err != nil {
				var sqliteErr *sqlite.Error
				if errors.As(err, &sqliteErr) && (sqliteErr.Code()&0xff == 5 || sqliteErr.Code()&0xff == 6) {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(5 * time.Millisecond):
					}
					continue
				}
				return errors.New("SQLite online backup failed")
			}
			if !more {
				return nil
			}
		}
	})
}

var toolVersion = regexp.MustCompile(`^pg_(dump|restore) \(PostgreSQL\) ([0-9]+)\.`)

var postgresParameters = map[string]string{
	"host": "PGHOST", "port": "PGPORT", "user": "PGUSER", "password": "PGPASSWORD", "dbname": "PGDATABASE",
	"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY", "connect_timeout": "PGCONNECT_TIMEOUT",
}

// postgresEnvironment turns the registry's DSN into libpq environment
// variables, so the password never appears in a process listing. Parameters
// it does not know are refused rather than silently dropped.
func postgresEnvironment(dsn string) ([]string, error) {
	values := make(map[string]string)
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		parsed, err := url.Parse(dsn)
		if err != nil {
			return nil, errors.New("PostgreSQL DSN could not be parsed for backup tools")
		}
		if parsed.User != nil {
			values["user"] = parsed.User.Username()
			if password, ok := parsed.User.Password(); ok {
				values["password"] = password
			}
		}
		if parsed.Hostname() != "" {
			values["host"] = parsed.Hostname()
		}
		if parsed.Port() != "" {
			values["port"] = parsed.Port()
		}
		if name := strings.TrimPrefix(parsed.Path, "/"); name != "" {
			values["dbname"] = name
		}
		for key, list := range parsed.Query() {
			if len(list) != 1 {
				return nil, errors.New("PostgreSQL DSN repeats a parameter")
			}
			values[key] = list[0]
		}
	} else {
		for _, field := range strings.Fields(dsn) {
			key, value, found := strings.Cut(field, "=")
			if !found || strings.ContainsAny(value, "'\\") {
				return nil, errors.New("PostgreSQL DSN uses quoting the backup tools do not support; use a URL DSN")
			}
			values[key] = value
		}
	}
	environment := make([]string, 0, len(values))
	for key, value := range values {
		name, known := postgresParameters[key]
		if !known {
			return nil, fmt.Errorf("PostgreSQL DSN parameter %q is not supported by the backup tools", key)
		}
		environment = append(environment, name+"="+value)
	}
	sort.Strings(environment)
	return environment, nil
}

// postgresDatabaseName returns the database name of a DSN; pg_restore needs
// it explicitly, while the other connection details come from the
// environment.
func postgresDatabaseName(dsn string) (string, error) {
	environment, err := postgresEnvironment(dsn)
	if err != nil {
		return "", err
	}
	for _, entry := range environment {
		if name, found := strings.CutPrefix(entry, "PGDATABASE="); found && name != "" {
			return name, nil
		}
	}
	return "", errors.New("PostgreSQL DSN does not name a database")
}

// postgresTool runs a PostgreSQL client with the connection passed in the
// environment, never on the command line.
func postgresTool(ctx context.Context, executable, dsn string, stdout io.Writer, stdin io.Reader, args ...string) error {
	command := exec.CommandContext(ctx, executable, args...)
	// libpq reads the connection string from PGDATABASE when it is a
	// conninfo string, which keeps passwords out of the process list.
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "PGCONNECT_TIMEOUT=30"}
	if dsn != "" {
		environment, err := postgresEnvironment(dsn)
		if err != nil {
			return err
		}
		command.Env = append(command.Env, environment...)
	}
	var diagnostic bytes.Buffer
	command.Stdout, command.Stdin, command.Stderr = stdout, stdin, &limitedBuffer{buffer: &diagnostic, remaining: 4096}
	command.WaitDelay = 5 * time.Second
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s failed: %w: %s", filepath.Base(executable), err, strings.TrimSpace(diagnostic.String()))
	}
	if diagnostic.Len() > 0 {
		return fmt.Errorf("%s reported: %s", filepath.Base(executable), strings.TrimSpace(diagnostic.String()))
	}
	return nil
}

func postgresMajor(ctx context.Context, db *sql.DB, executable string) error {
	var serverVersion int
	if err := db.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&serverVersion); err != nil {
		return errors.New("PostgreSQL server version could not be read")
	}
	var output bytes.Buffer
	if err := postgresTool(ctx, executable, "", &output, nil, "--version"); err != nil {
		return err
	}
	match := toolVersion.FindStringSubmatch(output.String())
	if match == nil {
		return errors.New("PostgreSQL tool version could not be recognized")
	}
	if match[2] != fmt.Sprint(serverVersion/10000) {
		return fmt.Errorf("%s major %s does not match server major %d", filepath.Base(executable), match[2], serverVersion/10000)
	}
	return nil
}

// postgresDump exports a snapshot, reads the object references inside it and
// runs pg_dump on the same snapshot while the exporting transaction is open.
func postgresDump(ctx context.Context, db *sql.DB, dsn, pgDump, destination string) (string, map[storage.ObjectKey]struct{}, error) {
	if pgDump == "" {
		pgDump = "pg_dump"
	}
	if err := postgresMajor(ctx, db, pgDump); err != nil {
		return "", nil, err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return "", nil, errors.New("PostgreSQL snapshot connection could not be opened")
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return "", nil, errors.New("PostgreSQL snapshot could not start")
	}
	defer func() { _ = tx.Rollback() }()
	var snapshot, installation string
	if err := tx.QueryRowContext(ctx, `SELECT pg_export_snapshot()`).Scan(&snapshot); err != nil {
		return "", nil, errors.New("PostgreSQL snapshot could not be exported")
	}
	if err := tx.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&installation); err != nil {
		return "", nil, errors.New("installation identity could not be read")
	}
	referenced, err := referencesInTx(ctx, tx)
	if err != nil {
		return "", nil, err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", nil, errors.New("database staging file could not be opened")
	}
	dumpErr := postgresTool(ctx, pgDump, dsn, &limitedWriter{writer: output, remaining: maxDumpBytes}, nil, "--format=custom", "--no-owner", "--no-acl", "--no-password", "--snapshot="+snapshot)
	if err := errors.Join(dumpErr, output.Sync(), output.Close()); err != nil {
		return "", nil, err
	}
	return installation, referenced, nil
}

// referencesInTx reads object references inside an existing transaction.
func referencesInTx(ctx context.Context, tx *sql.Tx) (map[storage.ObjectKey]struct{}, error) {
	return objectmaint.RequiredObjectsTx(ctx, tx)
}

// ListBackups returns the IDs of complete backups, newest first.
func ListBackups(ctx context.Context, bucket Bucket) ([]string, error) {
	found, err := bucket.list(ctx, "backups/")
	if err != nil {
		return nil, fmt.Errorf("backups could not be listed: %w", err)
	}
	var ids []string
	prefix := bucket.key("backups") + "/"
	for key := range found {
		id, rest, ok := strings.Cut(strings.TrimPrefix(key, prefix), "/")
		if ok && rest == "manifest.json" && backupIDPattern.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	return ids, nil
}

// applyRetention keeps the newest retain complete backups, deletes the
// others, then deletes objects that no remaining manifest lists. Incomplete
// backups (no manifest) older than a day are removed too.
func applyRetention(ctx context.Context, bucket Bucket, retain int) ([]string, error) {
	ids, err := ListBackups(ctx, bucket)
	if err != nil {
		return nil, err
	}
	keep := make(map[string]struct{})
	for index, id := range ids {
		if index < retain {
			keep[id] = struct{}{}
		}
	}
	all, err := bucket.list(ctx, "backups/")
	if err != nil {
		return nil, err
	}
	prefix := bucket.key("backups") + "/"
	var removed []string
	removedSet := make(map[string]bool)
	for key := range all {
		id, _, ok := strings.Cut(strings.TrimPrefix(key, prefix), "/")
		if !ok || !backupIDPattern.MatchString(id) {
			continue
		}
		if _, kept := keep[id]; kept {
			continue
		}
		complete := false
		for _, candidate := range ids {
			if candidate == id {
				complete = true
			}
		}
		if !complete {
			created, err := time.Parse("20060102T150405Z", strings.SplitN(id, "-", 2)[0])
			if err != nil || time.Since(created) < 24*time.Hour {
				continue
			}
		}
		if err := bucket.delete(ctx, key); err != nil {
			return removed, err
		}
		if !removedSet[id] {
			removedSet[id] = true
			removed = append(removed, id)
		}
	}
	listed := make(map[string]struct{})
	for id := range keep {
		manifest, err := readManifest(ctx, bucket, id)
		if err != nil {
			return removed, fmt.Errorf("retained backup %s is unreadable; no objects were collected: %w", id, err)
		}
		for _, object := range manifest.Objects {
			listed[bucket.key("objects", object.WorkspaceID, object.SHA256+".age")] = struct{}{}
		}
	}
	objects, err := bucket.list(ctx, "objects/")
	if err != nil {
		return removed, err
	}
	for key := range objects {
		if _, needed := listed[key]; needed {
			continue
		}
		if err := bucket.delete(ctx, key); err != nil {
			return removed, err
		}
	}
	sort.Strings(removed)
	return removed, nil
}

func readManifest(ctx context.Context, bucket Bucket, id string) (Manifest, error) {
	if !backupIDPattern.MatchString(id) {
		return Manifest{}, errors.New("backup ID is invalid")
	}
	var document bytes.Buffer
	if err := bucket.get(ctx, bucket.key("backups", id, "manifest.json"), maxManifestBytes, &document); err != nil {
		return Manifest{}, fmt.Errorf("backup manifest could not be read: %w", err)
	}
	var manifest Manifest
	decoder := json.NewDecoder(&document)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || manifest.Version != manifestVersion || manifest.ID != id || len(manifest.DatabaseSHA256) != 64 {
		return Manifest{}, errors.New("backup manifest is malformed")
	}
	if _, err := uuid.Parse(manifest.InstallationID); err != nil {
		return Manifest{}, errors.New("backup manifest is malformed")
	}
	for _, object := range manifest.Objects {
		if _, err := storage.NewObjectKey(object.WorkspaceID, object.SHA256); err != nil || object.Size < 0 {
			return Manifest{}, errors.New("backup manifest lists a malformed object")
		}
	}
	return manifest, nil
}

type limitedBuffer struct {
	buffer    *bytes.Buffer
	remaining int
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	keep := data
	if len(keep) > b.remaining {
		keep = keep[:b.remaining]
	}
	b.buffer.Write(keep)
	b.remaining -= len(keep)
	return len(data), nil
}

type limitedWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *limitedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, errors.New("database dump exceeds its size limit")
	}
	w.remaining -= int64(len(data))
	return w.writer.Write(data)
}

// removeDatabaseFiles removes a staged SQLite file and any sidecar a reader
// created next to it.
func removeDatabaseFiles(path string) {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		_ = os.Remove(path + suffix)
	}
}
