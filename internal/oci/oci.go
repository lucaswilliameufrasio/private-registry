// Package oci implements an experimental, self-contained OCI Distribution
// registry backend. Blobs live in the shared content-addressed object store;
// manifests, tags and blob membership live in the registry database, so that
// every publication commits in the same transaction that revalidates the
// publisher's current grant. No external registry engine is involved.
package oci

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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

const (
	MaxManifestBytes  = 4 << 20
	maxReferences     = 1000
	uploadIdleTimeout = time.Hour
	maxImageNameBytes = 180

	MediaTypeOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex       = "application/vnd.oci.image.index.v1+json"
	MediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
)

var (
	ErrUnauthorized     = errors.New("OCI credential is missing, invalid or lacks the required grant")
	ErrNameInvalid      = errors.New("OCI image name is invalid")
	ErrDigestInvalid    = errors.New("OCI digest is invalid or does not match the content")
	ErrBlobUnknown      = errors.New("OCI blob is unknown to this repository")
	ErrManifestUnknown  = errors.New("OCI manifest is unknown to this repository")
	ErrManifestInvalid  = errors.New("OCI manifest is invalid or unsupported")
	ErrManifestBlob     = errors.New("OCI manifest references content that was not uploaded to this repository")
	ErrUploadUnknown    = errors.New("OCI upload session is unknown")
	ErrUploadRange      = errors.New("OCI upload chunk is out of order")
	ErrTooLarge         = errors.New("OCI content exceeds the configured size limit")
	ErrBusy             = errors.New("OCI upload capacity is temporarily full")
	ErrUnavailable      = errors.New("OCI registry is temporarily unavailable")
	digestPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tagPattern          = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)
	nameComponent       = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*$`)
	manifestMediaTypes  = map[string]bool{MediaTypeOCIManifest: false, MediaTypeDockerManifest: false, MediaTypeOCIIndex: true, MediaTypeDockerList: true}
	errSessionInUse     = errors.New("OCI upload session is in use")
	errStagingUnwritten = errors.New("OCI upload staging could not be written")
)

type Options struct {
	// StagingDirectory holds in-progress uploads. It is emptied at startup:
	// upload sessions do not survive a restart and clients retry the blob.
	StagingDirectory string
	MaxBlobBytes     int64
	MaxUploads       int
}

type Service struct {
	db       *sql.DB
	driver   config.DatabaseDriver
	repos    *repositories.Service
	store    storage.Driver
	staging  string
	maxBlob  int64
	maxLive  int
	mu       sync.Mutex
	sessions map[string]*upload
}

type upload struct {
	workspace  string
	repository string
	user       string
	path       string
	size       int64
	touched    time.Time
	busy       bool
}

// Principal is the outcome of one credential check. It is valid for a single
// request; every write revalidates the credential inside its transaction.
type Principal struct {
	UserID   string
	CanRead  bool
	CanWrite bool
	bearer   string
}

type Manifest struct {
	Digest    string
	MediaType string
	Content   []byte
}

func New(db *sql.DB, driver config.DatabaseDriver, repos *repositories.Service, store storage.Driver, options Options) (*Service, error) {
	if db == nil || repos == nil || store == nil || (driver != config.SQLite && driver != config.Postgres) || options.MaxBlobBytes < 1 || options.MaxUploads < 1 || options.MaxUploads > 1024 {
		return nil, errors.New("OCI service configuration is invalid")
	}
	staging, err := filepath.Abs(options.StagingDirectory)
	if err != nil || options.StagingDirectory == "" {
		return nil, errors.New("OCI staging directory is invalid")
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return nil, errors.New("OCI staging directory could not be created")
	}
	info, err := os.Lstat(staging)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("OCI staging directory must be a private directory")
	}
	entries, err := os.ReadDir(staging)
	if err != nil {
		return nil, errors.New("OCI staging directory could not be read")
	}
	for _, entry := range entries {
		// Only files this service names are removed; anything else is left
		// for the operator to inspect.
		if entry.Type().IsRegular() && strings.HasPrefix(entry.Name(), "upload-") {
			if err := os.Remove(filepath.Join(staging, entry.Name())); err != nil {
				return nil, errors.New("stale OCI upload could not be removed")
			}
		}
	}
	return &Service{db: db, driver: driver, repos: repos, store: store, staging: staging, maxBlob: options.MaxBlobBytes, maxLive: options.MaxUploads, sessions: make(map[string]*upload)}, nil
}

// ValidImageName reports whether name is a lower-case OCI path such as
// "team/app". The workspace and repository identifiers are not part of it.
func ValidImageName(name string) bool {
	if name == "" || len(name) > maxImageNameBytes {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		if !nameComponent.MatchString(component) {
			return false
		}
	}
	return true
}

func ValidDigest(digest string) bool { return digestPattern.MatchString(digest) }

func ValidTag(tag string) bool { return tagPattern.MatchString(tag) }

// Authorize checks one bearer for a repository. A write token ("prow_")
// proves a current publisher grant and additionally allows reads when its
// owner currently holds a reader grant; a personal read token allows reads
// only. Unknown, expired, revoked or mismatched credentials are
// indistinguishable to the caller.
func (s *Service) Authorize(ctx context.Context, bearer, workspace, repository string) (Principal, error) {
	if s == nil || ctx == nil {
		return Principal{}, ErrUnavailable
	}
	if strings.HasPrefix(bearer, "prow_") {
		var user string
		err := s.repos.WithOCIWriteTokenTransaction(ctx, bearer, workspace, repository, func(_ *sql.Tx, actor string) error {
			user = actor
			return nil
		})
		if errors.Is(err, repositories.ErrOCIWriteTokenUnavailable) {
			return Principal{}, ErrUnauthorized
		} else if err != nil {
			return Principal{}, ErrUnavailable
		}
		canRead, err := s.repos.HasRepositoryGrant(ctx, user, workspace, repository, repositories.GrantReader)
		if err != nil {
			canRead = false
		}
		return Principal{UserID: user, CanRead: canRead, CanWrite: true, bearer: bearer}, nil
	}
	var user string
	err := s.repos.WithPersonalReadTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		user = actor
		return repositories.RequireFormat(ctx, tx, s.driver, workspace, repository, repositories.FormatOCI)
	})
	if errors.Is(err, repositories.ErrPersonalTokenUnavailable) || errors.Is(err, repositories.ErrFormatMismatch) || errors.Is(err, repositories.ErrRepositoryUnavailable) {
		return Principal{}, ErrUnauthorized
	} else if err != nil {
		return Principal{}, ErrUnavailable
	}
	return Principal{UserID: user, CanRead: true, bearer: bearer}, nil
}

// StartUpload opens a resumable blob upload owned by the principal.
func (s *Service) StartUpload(principal Principal, workspace, repository string) (string, error) {
	if !principal.CanWrite {
		return "", ErrUnauthorized
	}
	id := uuid.NewString()
	path := filepath.Join(s.staging, "upload-"+id)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, session := range s.sessions {
		if !session.busy && now.Sub(session.touched) > uploadIdleTimeout {
			_ = os.Remove(session.path)
			delete(s.sessions, key)
		}
	}
	if len(s.sessions) >= s.maxLive {
		return "", ErrBusy
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", ErrUnavailable
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", ErrUnavailable
	}
	s.sessions[id] = &upload{workspace: workspace, repository: repository, user: principal.UserID, path: path, touched: now}
	return id, nil
}

// acquire hands one request exclusive use of a session. A session is only
// visible to the user and repository that created it.
func (s *Service) acquire(principal Principal, workspace, repository, id string) (*upload, error) {
	if !principal.CanWrite {
		return nil, ErrUnauthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok || session.workspace != workspace || session.repository != repository || session.user != principal.UserID {
		return nil, ErrUploadUnknown
	}
	if session.busy {
		return nil, errSessionInUse
	}
	session.busy = true
	return session, nil
}

func (s *Service) release(session *upload) {
	s.mu.Lock()
	session.busy = false
	session.touched = time.Now()
	s.mu.Unlock()
}

func (s *Service) discard(id string, session *upload) {
	_ = os.Remove(session.path)
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// UploadSize reports the bytes received so far.
func (s *Service) UploadSize(principal Principal, workspace, repository, id string) (int64, error) {
	session, err := s.acquire(principal, workspace, repository, id)
	if err != nil {
		return 0, uploadError(err)
	}
	defer s.release(session)
	return session.size, nil
}

// AppendUpload appends one chunk. offset is the client's declared start, or a
// negative value when the client sent no Content-Range.
func (s *Service) AppendUpload(ctx context.Context, principal Principal, workspace, repository, id string, offset int64, chunk io.Reader) (int64, error) {
	session, err := s.acquire(principal, workspace, repository, id)
	if err != nil {
		return 0, uploadError(err)
	}
	defer s.release(session)
	if offset >= 0 && offset != session.size {
		return session.size, ErrUploadRange
	}
	if err := s.append(ctx, session, chunk); err != nil {
		return session.size, err
	}
	return session.size, nil
}

func (s *Service) append(ctx context.Context, session *upload, chunk io.Reader) error {
	if chunk == nil {
		return nil
	}
	file, err := os.OpenFile(session.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return ErrUnavailable
	}
	remaining := s.maxBlob - session.size
	written, copyErr := io.Copy(file, io.LimitReader(contextReader{ctx: ctx, reader: chunk}, remaining+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written > remaining {
		// A partial chunk would corrupt the next append, so the file is cut
		// back to the last acknowledged size.
		if err := os.Truncate(session.path, session.size); err != nil {
			return errStagingUnwritten
		}
		if written > remaining {
			return ErrTooLarge
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrUnavailable
	}
	session.size += written
	return nil
}

// FinishUpload verifies the declared digest over everything received, stores
// the blob and records it for the repository in the transaction that
// revalidates the write token. The session ends whether or not this succeeds
// on a digest mismatch; transient failures keep it so the client may retry.
func (s *Service) FinishUpload(ctx context.Context, principal Principal, workspace, repository, id, digest string, last io.Reader) (int64, error) {
	if !ValidDigest(digest) {
		return 0, ErrDigestInvalid
	}
	session, err := s.acquire(principal, workspace, repository, id)
	if err != nil {
		return 0, uploadError(err)
	}
	if err := s.append(ctx, session, last); err != nil {
		s.release(session)
		return 0, err
	}
	file, err := os.Open(session.path)
	if err != nil {
		s.release(session)
		return 0, ErrUnavailable
	}
	hasher := sha256.New()
	size, err := io.Copy(hasher, contextReader{ctx: ctx, reader: file})
	if err != nil || size != session.size {
		_ = file.Close()
		s.release(session)
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, ErrUnavailable
	}
	if "sha256:"+hex.EncodeToString(hasher.Sum(nil)) != digest {
		_ = file.Close()
		s.discard(id, session)
		return 0, ErrDigestInvalid
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		s.release(session)
		return 0, ErrUnavailable
	}
	info, putErr := s.store.Put(ctx, workspace, file, s.maxBlob)
	closeErr := file.Close()
	if putErr != nil || closeErr != nil || "sha256:"+info.Key.SHA256 != digest || info.Size != size {
		s.release(session)
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, ErrUnavailable
	}
	if err := s.recordBlob(ctx, principal, workspace, repository, digest, size); err != nil {
		s.release(session)
		return 0, err
	}
	s.discard(id, session)
	return size, nil
}

func (s *Service) CancelUpload(principal Principal, workspace, repository, id string) error {
	session, err := s.acquire(principal, workspace, repository, id)
	if err != nil {
		return uploadError(err)
	}
	s.discard(id, session)
	return nil
}

func uploadError(err error) error {
	if errors.Is(err, errSessionInUse) {
		return ErrUploadRange
	}
	return err
}

func (s *Service) recordBlob(ctx context.Context, principal Principal, workspace, repository, digest string, size int64) error {
	err := s.repos.WithOCIWriteTokenTransaction(ctx, principal.bearer, workspace, repository, func(tx *sql.Tx, user string) error {
		query := `INSERT INTO registry_oci_blobs (repository_id, workspace_id, digest, size_bytes, created_by, created_at_ms) VALUES (` + s.binds(6) + `) ON CONFLICT (repository_id, digest) DO NOTHING`
		if _, err := tx.ExecContext(ctx, query, repository, workspace, digest, size, user, time.Now().UTC().UnixMilli()); err != nil {
			return ErrUnavailable
		}
		return nil
	})
	return writeError(err)
}

func writeError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, repositories.ErrOCIWriteTokenUnavailable):
		return ErrUnauthorized
	case errors.Is(err, ErrManifestBlob), errors.Is(err, ErrManifestInvalid), errors.Is(err, ErrDigestInvalid):
		return err
	default:
		return ErrUnavailable
	}
}

// StatBlob reports a blob that was uploaded to this repository. Knowing a
// digest from another repository or workspace never makes it visible here.
func (s *Service) StatBlob(ctx context.Context, repository, digest string) (int64, error) {
	if !ValidDigest(digest) {
		return 0, ErrDigestInvalid
	}
	var size int64
	err := s.db.QueryRowContext(ctx, `SELECT size_bytes FROM registry_oci_blobs WHERE repository_id = `+s.bind(1)+` AND digest = `+s.bind(2), repository, digest).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrBlobUnknown
	} else if err != nil {
		return 0, ErrUnavailable
	}
	return size, nil
}

// OpenBlob returns the verified bytes of a blob known to this repository.
func (s *Service) OpenBlob(ctx context.Context, workspace, repository, digest string) (io.ReadCloser, int64, error) {
	size, err := s.StatBlob(ctx, repository, digest)
	if err != nil {
		return nil, 0, err
	}
	reader, info, err := s.store.Open(ctx, storage.ObjectKey{WorkspaceID: workspace, SHA256: strings.TrimPrefix(digest, "sha256:")})
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	if info.Size != size {
		_ = reader.Close()
		return nil, 0, ErrUnavailable
	}
	return reader, size, nil
}

type descriptor struct {
	MediaType string   `json:"mediaType"`
	Digest    string   `json:"digest"`
	Size      *int64   `json:"size"`
	URLs      []string `json:"urls"`
}

type manifestDocument struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        *descriptor  `json:"config"`
	Layers        []descriptor `json:"layers"`
	Manifests     []descriptor `json:"manifests"`
}

// PutManifest validates and commits a manifest and, when reference is a tag,
// moves that tag. Everything the manifest references must already have been
// uploaded to this repository. Tags are mutable; digests are immutable.
func (s *Service) PutManifest(ctx context.Context, principal Principal, workspace, repository, image, reference, contentType string, body []byte) (string, error) {
	if !principal.CanWrite {
		return "", ErrUnauthorized
	}
	if !ValidImageName(image) {
		return "", ErrNameInvalid
	}
	if len(body) < 2 || len(body) > MaxManifestBytes {
		return "", ErrManifestInvalid
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	tag := ""
	switch {
	case ValidDigest(reference):
		if reference != digest {
			return "", ErrDigestInvalid
		}
	case ValidTag(reference):
		tag = reference
	default:
		return "", ErrManifestInvalid
	}
	var document manifestDocument
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&document); err != nil || decoder.More() || document.SchemaVersion != 2 {
		return "", ErrManifestInvalid
	}
	mediaType := contentType
	if mediaType == "" {
		mediaType = document.MediaType
	}
	isIndex, known := manifestMediaTypes[mediaType]
	if !known || (document.MediaType != "" && document.MediaType != mediaType) {
		return "", ErrManifestInvalid
	}
	var blobs, children []string
	if isIndex {
		if document.Config != nil || len(document.Layers) != 0 || len(document.Manifests) > maxReferences {
			return "", ErrManifestInvalid
		}
		for _, child := range document.Manifests {
			if !ValidDigest(child.Digest) {
				return "", ErrManifestInvalid
			}
			children = append(children, child.Digest)
		}
	} else {
		if document.Config == nil || len(document.Manifests) != 0 || len(document.Layers) > maxReferences {
			return "", ErrManifestInvalid
		}
		for _, item := range append([]descriptor{*document.Config}, document.Layers...) {
			// Foreign layers would make the registry vouch for bytes it does
			// not hold.
			if !ValidDigest(item.Digest) || len(item.URLs) != 0 || item.Size == nil || *item.Size < 0 {
				return "", ErrManifestInvalid
			}
			blobs = append(blobs, item.Digest)
		}
	}
	err := s.repos.WithOCIWriteTokenTransaction(ctx, principal.bearer, workspace, repository, func(tx *sql.Tx, user string) error {
		for _, blob := range blobs {
			var present bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_oci_blobs WHERE repository_id = `+s.bind(1)+` AND digest = `+s.bind(2)+`)`, repository, blob).Scan(&present); err != nil {
				return ErrUnavailable
			}
			if !present {
				return ErrManifestBlob
			}
		}
		for _, child := range children {
			var present bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_oci_manifests WHERE repository_id = `+s.bind(1)+` AND digest = `+s.bind(2)+`)`, repository, child).Scan(&present); err != nil {
				return ErrUnavailable
			}
			if !present {
				return ErrManifestBlob
			}
		}
		now := time.Now().UTC().UnixMilli()
		query := `INSERT INTO registry_oci_manifests (repository_id, workspace_id, digest, media_type, content, created_by, created_at_ms) VALUES (` + s.binds(7) + `) ON CONFLICT (repository_id, digest) DO NOTHING`
		if _, err := tx.ExecContext(ctx, query, repository, workspace, digest, mediaType, body, user, now); err != nil {
			return ErrUnavailable
		}
		for kind, targets := range map[string][]string{"blob": blobs, "manifest": children} {
			for _, target := range targets {
				query := `INSERT INTO registry_oci_manifest_references (repository_id, manifest_digest, referenced_digest, kind) VALUES (` + s.binds(4) + `) ON CONFLICT DO NOTHING`
				if _, err := tx.ExecContext(ctx, query, repository, digest, target, kind); err != nil {
					return ErrUnavailable
				}
			}
		}
		if tag != "" {
			query := `INSERT INTO registry_oci_tags (repository_id, image_name, tag, manifest_digest, updated_by, updated_at_ms) VALUES (` + s.binds(6) + `) ON CONFLICT (repository_id, image_name, tag) DO UPDATE SET manifest_digest = excluded.manifest_digest, updated_by = excluded.updated_by, updated_at_ms = excluded.updated_at_ms`
			if _, err := tx.ExecContext(ctx, query, repository, image, tag, digest, user, now); err != nil {
				return ErrUnavailable
			}
		}
		return s.audit(ctx, tx, user, repository, image, digest)
	})
	if err != nil {
		return "", writeError(err)
	}
	return digest, nil
}

func (s *Service) audit(ctx context.Context, tx *sql.Tx, user, repository, image, digest string) error {
	eventID, err := uuid.NewV7()
	if err != nil {
		return ErrUnavailable
	}
	target := repository + "/" + image + "@" + digest
	query := `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, actor_label, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'user', NULL, 'oci_manifest.published', 'oci_manifest', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
	if _, err := tx.ExecContext(ctx, query, eventID.String(), user, target, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return ErrUnavailable
	}
	return nil
}

// GetManifest resolves a tag of the given image, or a digest within the
// repository.
func (s *Service) GetManifest(ctx context.Context, repository, image, reference string) (Manifest, error) {
	if !ValidImageName(image) {
		return Manifest{}, ErrNameInvalid
	}
	digest := reference
	if !ValidDigest(reference) {
		if !ValidTag(reference) {
			return Manifest{}, ErrManifestUnknown
		}
		err := s.db.QueryRowContext(ctx, `SELECT manifest_digest FROM registry_oci_tags WHERE repository_id = `+s.bind(1)+` AND image_name = `+s.bind(2)+` AND tag = `+s.bind(3), repository, image, reference).Scan(&digest)
		if errors.Is(err, sql.ErrNoRows) {
			return Manifest{}, ErrManifestUnknown
		} else if err != nil {
			return Manifest{}, ErrUnavailable
		}
	}
	manifest := Manifest{Digest: digest}
	err := s.db.QueryRowContext(ctx, `SELECT media_type, content FROM registry_oci_manifests WHERE repository_id = `+s.bind(1)+` AND digest = `+s.bind(2), repository, digest).Scan(&manifest.MediaType, &manifest.Content)
	if errors.Is(err, sql.ErrNoRows) {
		return Manifest{}, ErrManifestUnknown
	} else if err != nil {
		return Manifest{}, ErrUnavailable
	}
	sum := sha256.Sum256(manifest.Content)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return Manifest{}, ErrUnavailable
	}
	return manifest, nil
}

// ListTags returns up to limit tags after last, in lexical order.
func (s *Service) ListTags(ctx context.Context, repository, image, last string, limit int) ([]string, error) {
	if !ValidImageName(image) {
		return nil, ErrNameInvalid
	}
	if limit < 1 || limit > 1000 || len(last) > 128 {
		return nil, ErrManifestInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT tag FROM registry_oci_tags WHERE repository_id = `+s.bind(1)+` AND image_name = `+s.bind(2)+` AND tag > `+s.bind(3)+` ORDER BY tag LIMIT `+s.bind(4), repository, image, last, limit)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	tags := make([]string, 0, 16)
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return nil, ErrUnavailable
		}
		tags = append(tags, tag)
	}
	if err := rows.Err(); err != nil {
		return nil, ErrUnavailable
	}
	return tags, nil
}

func (s *Service) bind(position int) string {
	if s.driver == config.Postgres {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}

func (s *Service) binds(count int) string {
	parts := make([]string, count)
	for index := range parts {
		parts[index] = s.bind(index + 1)
	}
	return strings.Join(parts, ", ")
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
