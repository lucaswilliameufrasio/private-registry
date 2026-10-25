package artifacts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

const (
	DefaultUploadSessionTTL = 24 * time.Hour
	SchemaMaxUploadBytes    = int64(1 << 30)
	MaxCollectionFiles      = 10000
	uploadClaimCleanupLimit = 5 * time.Second
)

var (
	ErrInvalidCollectionName     = errors.New("artifact collection name is invalid")
	ErrInvalidVersionLabel       = errors.New("artifact version label is invalid")
	ErrInvalidArtifactPath       = errors.New("artifact path is invalid")
	ErrInvalidContentType        = errors.New("artifact content type is invalid")
	ErrInvalidArtifactSize       = errors.New("artifact size is invalid")
	ErrInvalidDigest             = errors.New("artifact digest is invalid")
	ErrArtifactNotFound          = errors.New("artifact is unavailable")
	ErrVersionConflict           = errors.New("artifact version already exists or is unavailable")
	ErrPathConflict              = errors.New("artifact path is already reserved")
	ErrUploadNotFound            = errors.New("upload session is unavailable")
	ErrUploadExpired             = errors.New("upload session has expired")
	ErrUploadStateConflict       = errors.New("upload session is not receiving content")
	ErrUploadTooLarge            = errors.New("artifact exceeds the configured upload limit")
	ErrUploadDigestMismatch      = errors.New("uploaded artifact does not match its declared digest")
	ErrUploadSizeMismatch        = errors.New("uploaded artifact does not match its declared size")
	ErrUploadCapacity            = errors.New("artifact upload capacity is temporarily unavailable")
	ErrVersionIncomplete         = errors.New("artifact version has incomplete uploads")
	ErrVersionEmpty              = errors.New("artifact version has no files")
	ErrInvalidRange              = errors.New("artifact byte range is invalid")
	ErrArtifactIntegrity         = errors.New("artifact storage metadata does not match the catalog")
	ErrDownloadTicketUnavailable = errors.New("download ticket is unavailable")

	collectionNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	versionLabelPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	sha256Pattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	artifactPathPattern   = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

type Options struct {
	MaxUploadBytes       int64
	MaxConcurrentUploads int
	SessionTTL           time.Duration
}

type Service struct {
	db             *sql.DB
	driver         config.DatabaseDriver
	repositories   *repositories.Service
	storage        storage.Driver
	maxUploadBytes int64
	sessionTTL     time.Duration
	uploadSlots    chan struct{}
}

type StartUploadRequest struct {
	Collection  string
	Version     string
	Path        string
	ContentType string
	Size        int64
	SHA256      string
}

type UploadSession struct {
	ID                string
	ArtifactVersionID string
	WorkspaceID       string
	RepositoryID      string
	Path              string
	ContentType       string
	ExpectedSize      int64
	ExpectedSHA256    string
	Status            string
	ExpiresAt         time.Time
}

type ArtifactVersion struct {
	ID           string
	WorkspaceID  string
	RepositoryID string
	Collection   string
	Version      string
	Status       string
	CreatedBy    string
	CreatedAt    time.Time
	PublishedAt  *time.Time
	Files        []File
}

type File struct {
	ID          string
	Path        string
	ContentType string
	Size        int64
	SHA256      string
	CreatedBy   string
	CreatedAt   time.Time
}

type OpenedFile struct {
	File   File
	Reader io.ReadCloser
	Range  bool
}

type DownloadTicket struct {
	Token     string
	File      File
	ExpiresAt time.Time
}

func New(
	db *sql.DB,
	driver config.DatabaseDriver,
	repositoryService *repositories.Service,
	objectStore storage.Driver,
	options Options,
) (*Service, error) {
	if db == nil || repositoryService == nil || objectStore == nil {
		return nil, errors.New("artifact database, repository authorization, and storage are required")
	}
	if driver != config.SQLite && driver != config.Postgres {
		return nil, errors.New("artifact database driver must be sqlite or postgres")
	}
	if options.MaxUploadBytes < 1 || options.MaxUploadBytes > SchemaMaxUploadBytes {
		return nil, errors.New("artifact upload limit must be between 1 byte and 1 GiB")
	}
	if options.MaxConcurrentUploads < 1 || options.MaxConcurrentUploads > 128 {
		return nil, errors.New("concurrent artifact upload limit must be between 1 and 128")
	}
	if options.SessionTTL == 0 {
		options.SessionTTL = DefaultUploadSessionTTL
	}
	if options.SessionTTL < time.Minute || options.SessionTTL > 7*24*time.Hour {
		return nil, errors.New("artifact upload session lifetime must be between 1 minute and 7 days")
	}
	return &Service{
		db:             db,
		driver:         driver,
		repositories:   repositoryService,
		storage:        objectStore,
		maxUploadBytes: options.MaxUploadBytes,
		sessionTTL:     options.SessionTTL,
		uploadSlots:    make(chan struct{}, options.MaxConcurrentUploads),
	}, nil
}

func (s *Service) MaxUploadBytes() int64 {
	if s == nil {
		return 0
	}
	return s.maxUploadBytes
}

func (s *Service) StartUpload(
	ctx context.Context,
	actorUserID string,
	workspaceID string,
	repositoryID string,
	request StartUploadRequest,
) (UploadSession, error) {
	if s == nil || ctx == nil {
		return UploadSession{}, errors.New("artifact upload service is unavailable")
	}
	actorID, err := parseID(actorUserID, repositories.ErrUnauthenticated)
	if err != nil {
		return UploadSession{}, repositories.ErrUnauthenticated
	}
	workspaceID, err = parseID(workspaceID, repositories.ErrInvalidWorkspaceID)
	if err != nil {
		return UploadSession{}, repositories.ErrInvalidWorkspaceID
	}
	repositoryID, err = parseID(repositoryID, repositories.ErrInvalidRepositoryID)
	if err != nil {
		return UploadSession{}, repositories.ErrInvalidRepositoryID
	}
	request, err = validateStartUploadRequest(request, s.maxUploadBytes)
	if err != nil {
		return UploadSession{}, err
	}

	var session UploadSession
	err = s.repositories.WithRepositoryGrantTransaction(
		ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher,
		func(tx *sql.Tx) error {
			now := time.Now().UTC()
			versionID, err := s.findOrCreateVersion(ctx, tx, actorID, workspaceID, repositoryID, request, now)
			if err != nil {
				return err
			}
			if err := s.expireOldSessions(ctx, tx, versionID, now); err != nil {
				return err
			}
			pathExists, err := s.pathReserved(ctx, tx, versionID, request.Path)
			if err != nil {
				return err
			}
			if pathExists {
				return ErrPathConflict
			}
			sessionID, err := uuid.NewV7()
			if err != nil {
				return errors.New("upload session identity could not be generated")
			}
			expiresAt := now.Add(s.sessionTTL)
			query := `INSERT INTO registry_generic_upload_sessions
				(upload_session_id, artifact_version_id, workspace_id, repository_id, path,
				 content_type, expected_size, expected_sha256, status, created_by,
				 created_at, expires_at, updated_at)
				VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `,
				` + bind(s.driver, 6) + `, ` + bind(s.driver, 7) + `, ` + bind(s.driver, 8) + `, 'receiving', ` + bind(s.driver, 9) + `,
				` + bind(s.driver, 10) + `, ` + bind(s.driver, 11) + `, ` + bind(s.driver, 12) + `)`
			if _, err := tx.ExecContext(ctx, query,
				sessionID.String(), versionID, workspaceID, repositoryID, request.Path,
				request.ContentType, request.Size, request.SHA256, actorID,
				now.Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
				return errors.New("artifact upload session could not be created")
			}
			session = UploadSession{
				ID:                sessionID.String(),
				ArtifactVersionID: versionID,
				WorkspaceID:       workspaceID,
				RepositoryID:      repositoryID,
				Path:              request.Path,
				ContentType:       request.ContentType,
				ExpectedSize:      request.Size,
				ExpectedSHA256:    request.SHA256,
				Status:            "receiving",
				ExpiresAt:         expiresAt,
			}
			return nil
		},
	)
	if err != nil {
		return UploadSession{}, err
	}
	return session, nil
}

// ReceiveUpload claims a declared file before streaming it into private
// storage, then records its verified digest in a short transaction that
// rechecks the publisher grant. Failed uploads release their claim for retry;
// process crashes leave a claim that is expired lazily after the session TTL.
// Objects left behind by a failed final database commit require the future GC.
func (s *Service) ReceiveUpload(
	ctx context.Context,
	actorUserID string,
	workspaceID string,
	repositoryID string,
	uploadSessionID string,
	source io.Reader,
) (result UploadSession, retErr error) {
	if s == nil || ctx == nil || source == nil {
		return UploadSession{}, errors.New("artifact upload service, context, and stream are required")
	}
	actorID, err := parseID(actorUserID, repositories.ErrUnauthenticated)
	if err != nil {
		return UploadSession{}, repositories.ErrUnauthenticated
	}
	workspaceID, err = parseID(workspaceID, repositories.ErrInvalidWorkspaceID)
	if err != nil {
		return UploadSession{}, repositories.ErrInvalidWorkspaceID
	}
	repositoryID, err = parseID(repositoryID, repositories.ErrInvalidRepositoryID)
	if err != nil {
		return UploadSession{}, repositories.ErrInvalidRepositoryID
	}
	uploadSessionID, err = parseID(uploadSessionID, ErrUploadNotFound)
	if err != nil {
		return UploadSession{}, ErrUploadNotFound
	}

	granted, err := s.repositories.HasRepositoryGrant(ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher)
	if err != nil {
		return UploadSession{}, err
	}
	if !granted {
		return UploadSession{}, repositories.ErrForbidden
	}

	select {
	case s.uploadSlots <- struct{}{}:
		defer func() { <-s.uploadSlots }()
	case <-ctx.Done():
		return UploadSession{}, ctx.Err()
	default:
		return UploadSession{}, ErrUploadCapacity
	}
	claimUUID, err := uuid.NewV7()
	if err != nil {
		return UploadSession{}, errors.New("artifact upload claim could not be generated")
	}
	claimID := claimUUID.String()
	session, expired, err := s.claimUploadSession(ctx, actorID, workspaceID, repositoryID, uploadSessionID, claimID)
	if err != nil {
		return UploadSession{}, err
	}
	if expired {
		return UploadSession{}, ErrUploadExpired
	}

	claimActive := true
	defer func() {
		if !claimActive {
			return
		}
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), uploadClaimCleanupLimit)
		defer cancel()
		if err := s.restoreUploadClaim(cleanupContext, uploadSessionID, claimID); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()

	object, err := s.storage.Put(ctx, workspaceID, source, session.ExpectedSize)
	if err != nil {
		if errors.Is(err, storage.ErrObjectTooLarge) {
			return UploadSession{}, ErrUploadTooLarge
		}
		return UploadSession{}, err
	}
	if object.Size != session.ExpectedSize {
		if err := s.markUploadRejected(ctx, uploadSessionID, claimID, object.Key.SHA256, object.Size); err != nil {
			return UploadSession{}, errors.Join(ErrUploadSizeMismatch, err)
		}
		claimActive = false
		return UploadSession{}, ErrUploadSizeMismatch
	}
	if object.Key.SHA256 != session.ExpectedSHA256 {
		if err := s.markUploadRejected(ctx, uploadSessionID, claimID, object.Key.SHA256, object.Size); err != nil {
			return UploadSession{}, errors.Join(ErrUploadDigestMismatch, err)
		}
		claimActive = false
		return UploadSession{}, ErrUploadDigestMismatch
	}

	var expiredAfterStorage bool
	err = s.repositories.WithRepositoryGrantTransaction(
		ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher,
		func(tx *sql.Tx) error {
			var status string
			var createdBy string
			var expiresAt string
			var storedClaimID sql.NullString
			query := `SELECT status, created_by, expires_at, upload_claim_id FROM registry_generic_upload_sessions
				WHERE upload_session_id = ` + bind(s.driver, 1) + `
					AND workspace_id = ` + bind(s.driver, 2) + `
					AND repository_id = ` + bind(s.driver, 3)
			if err := tx.QueryRowContext(ctx, query, uploadSessionID, workspaceID, repositoryID).
				Scan(&status, &createdBy, &expiresAt, &storedClaimID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrUploadNotFound
				}
				return errors.New("artifact upload session could not be revalidated")
			}
			if createdBy != actorID {
				return ErrUploadNotFound
			}
			if status != "uploading" || !storedClaimID.Valid || storedClaimID.String != claimID {
				return ErrUploadStateConflict
			}
			updatedAt := time.Now().UTC()
			expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
			if err != nil {
				return errors.New("artifact upload session expiry is invalid")
			}
			if !updatedAt.Before(expiry) {
				update := `UPDATE registry_generic_upload_sessions SET status = 'expired', upload_claim_id = NULL, updated_at = ` + bind(s.driver, 1) +
					` WHERE upload_session_id = ` + bind(s.driver, 2) + ` AND status = 'uploading' AND upload_claim_id = ` + bind(s.driver, 3)
				result, err := tx.ExecContext(ctx, update, updatedAt.Format(time.RFC3339Nano), uploadSessionID, claimID)
				if err != nil {
					return errors.New("expired artifact upload session could not be recorded")
				}
				if err := requireSingleUploadRow(result); err != nil {
					return err
				}
				expiredAfterStorage = true
				return nil
			}
			update := `UPDATE registry_generic_upload_sessions
				SET status = 'uploaded', object_sha256 = ` + bind(s.driver, 1) + `, object_size = ` + bind(s.driver, 2) +
				`, upload_claim_id = NULL, updated_at = ` + bind(s.driver, 3) + `
				WHERE upload_session_id = ` + bind(s.driver, 4) + ` AND status = 'uploading' AND upload_claim_id = ` + bind(s.driver, 5)
			result, err := tx.ExecContext(ctx, update,
				object.Key.SHA256, object.Size, updatedAt.Format(time.RFC3339Nano), uploadSessionID, claimID)
			if err != nil {
				return errors.New("verified artifact upload could not be recorded")
			}
			if err := requireSingleUploadRow(result); err != nil {
				return errors.New("verified artifact upload result could not be checked")
			}
			session.Status = "uploaded"
			return nil
		},
	)
	if err != nil {
		return UploadSession{}, err
	}
	claimActive = false
	if expiredAfterStorage {
		return UploadSession{}, ErrUploadExpired
	}
	return session, nil
}

func (s *Service) Publish(
	ctx context.Context,
	actorUserID string,
	workspaceID string,
	repositoryID string,
	artifactVersionID string,
) (ArtifactVersion, error) {
	if s == nil || ctx == nil {
		return ArtifactVersion{}, errors.New("artifact service is unavailable")
	}
	actorID, err := parseID(actorUserID, repositories.ErrUnauthenticated)
	if err != nil {
		return ArtifactVersion{}, repositories.ErrUnauthenticated
	}
	workspaceID, err = parseID(workspaceID, repositories.ErrInvalidWorkspaceID)
	if err != nil {
		return ArtifactVersion{}, repositories.ErrInvalidWorkspaceID
	}
	repositoryID, err = parseID(repositoryID, repositories.ErrInvalidRepositoryID)
	if err != nil {
		return ArtifactVersion{}, repositories.ErrInvalidRepositoryID
	}
	artifactVersionID, err = parseID(artifactVersionID, ErrArtifactNotFound)
	if err != nil {
		return ArtifactVersion{}, ErrArtifactNotFound
	}

	var artifact ArtifactVersion
	err = s.repositories.WithRepositoryGrantTransaction(
		ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher,
		func(tx *sql.Tx) error {
			var createdAt string
			var publishedAt sql.NullString
			query := `SELECT collection_name, version_label, status, created_by, created_at, published_at
				FROM registry_generic_artifact_versions
				WHERE artifact_version_id = ` + bind(s.driver, 1) + `
					AND workspace_id = ` + bind(s.driver, 2) + ` AND repository_id = ` + bind(s.driver, 3)
			if err := tx.QueryRowContext(ctx, query, artifactVersionID, workspaceID, repositoryID).Scan(
				&artifact.Collection, &artifact.Version, &artifact.Status, &artifact.CreatedBy, &createdAt, &publishedAt); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrArtifactNotFound
				}
				return errors.New("artifact version could not be read")
			}
			artifact.ID = artifactVersionID
			artifact.WorkspaceID = workspaceID
			artifact.RepositoryID = repositoryID
			artifact.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
			if err != nil {
				return errors.New("artifact creation time is invalid")
			}
			if publishedAt.Valid {
				parsed, parseErr := time.Parse(time.RFC3339Nano, publishedAt.String)
				if parseErr != nil {
					return errors.New("artifact publication time is invalid")
				}
				artifact.PublishedAt = &parsed
			}
			if artifact.Status == "published" {
				files, fileErr := s.loadFiles(ctx, tx, artifactVersionID)
				if fileErr != nil {
					return fileErr
				}
				artifact.Files = files
				return nil
			}
			if artifact.Status != "receiving" {
				return ErrVersionConflict
			}

			now := time.Now().UTC()
			if err := s.expireOldSessions(ctx, tx, artifactVersionID, now); err != nil {
				return err
			}
			var activeReceiving bool
			query = `SELECT EXISTS (
				SELECT 1 FROM registry_generic_upload_sessions
				WHERE artifact_version_id = ` + bind(s.driver, 1) + ` AND status IN ('receiving', 'uploading')
			)`
			if err := tx.QueryRowContext(ctx, query, artifactVersionID).Scan(&activeReceiving); err != nil {
				return errors.New("artifact upload completion state could not be checked")
			}
			if activeReceiving {
				return ErrVersionIncomplete
			}
			var uploadedCount int
			query = `SELECT count(*) FROM registry_generic_upload_sessions
				WHERE artifact_version_id = ` + bind(s.driver, 1) + ` AND status = 'uploaded'`
			if err := tx.QueryRowContext(ctx, query, artifactVersionID).Scan(&uploadedCount); err != nil {
				return errors.New("artifact file count could not be checked")
			}
			if uploadedCount == 0 {
				return ErrVersionEmpty
			}
			if uploadedCount > MaxCollectionFiles {
				return ErrVersionConflict
			}

			files, err := s.loadUploadedSessions(ctx, tx, artifactVersionID)
			if err != nil {
				return err
			}
			for index := range files {
				fileID, idErr := uuid.NewV7()
				if idErr != nil {
					return errors.New("artifact file identity could not be generated")
				}
				files[index].ID = fileID.String()
				files[index].CreatedBy = actorID
				files[index].CreatedAt = now
				insert := `INSERT INTO registry_generic_artifact_files
					(artifact_file_id, artifact_version_id, workspace_id, repository_id, path,
					 content_type, size_bytes, sha256, created_by, created_at)
					VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `,
					` + bind(s.driver, 6) + `, ` + bind(s.driver, 7) + `, ` + bind(s.driver, 8) + `, ` + bind(s.driver, 9) + `, ` + bind(s.driver, 10) + `)`
				if _, err := tx.ExecContext(ctx, insert, files[index].ID, artifactVersionID, workspaceID, repositoryID,
					files[index].Path, files[index].ContentType, files[index].Size, files[index].SHA256,
					actorID, now.Format(time.RFC3339Nano)); err != nil {
					return errors.New("artifact file catalog entry could not be created")
				}
			}

			update := `UPDATE registry_generic_artifact_versions
				SET status = 'published', published_at = ` + bind(s.driver, 1) +
				` WHERE artifact_version_id = ` + bind(s.driver, 2) + ` AND status = 'receiving'`
			result, err := tx.ExecContext(ctx, update, now.Format(time.RFC3339Nano), artifactVersionID)
			if err != nil {
				return errors.New("artifact version could not be published")
			}
			rowsAffected, err := result.RowsAffected()
			if err != nil || rowsAffected != 1 {
				return errors.New("artifact publication result could not be checked")
			}
			update = `UPDATE registry_generic_upload_sessions
				SET status = 'published', updated_at = ` + bind(s.driver, 1) +
				` WHERE artifact_version_id = ` + bind(s.driver, 2) + ` AND status = 'uploaded'`
			if _, err := tx.ExecContext(ctx, update, now.Format(time.RFC3339Nano), artifactVersionID); err != nil {
				return errors.New("artifact upload receipts could not be finalized")
			}
			if err := recordAudit(ctx, tx, s.driver, actorID, "artifact.generic.published", "artifact_version", artifactVersionID); err != nil {
				return err
			}
			artifact.Status = "published"
			artifact.PublishedAt = &now
			artifact.Files = files
			return nil
		},
	)
	if err != nil {
		return ArtifactVersion{}, err
	}
	return artifact, nil
}

// OpenFile authorizes the current reader grant before it reads catalog metadata
// or opens the underlying object. It is intended for the separately configured
// asset-origin gateway, never for inline content on the administrative origin.
func (s *Service) OpenFile(
	ctx context.Context,
	userID string,
	workspaceID string,
	repositoryID string,
	fileID string,
	offset int64,
	length int64,
) (OpenedFile, error) {
	if s == nil || ctx == nil {
		return OpenedFile{}, errors.New("artifact read service is unavailable")
	}
	userID, err := parseID(userID, repositories.ErrUnauthenticated)
	if err != nil {
		return OpenedFile{}, repositories.ErrUnauthenticated
	}
	workspaceID, err = parseID(workspaceID, repositories.ErrInvalidWorkspaceID)
	if err != nil {
		return OpenedFile{}, repositories.ErrInvalidWorkspaceID
	}
	repositoryID, err = parseID(repositoryID, repositories.ErrInvalidRepositoryID)
	if err != nil {
		return OpenedFile{}, repositories.ErrInvalidRepositoryID
	}
	fileID, err = parseID(fileID, ErrArtifactNotFound)
	if err != nil {
		return OpenedFile{}, ErrArtifactNotFound
	}
	granted, err := s.repositories.HasRepositoryGrant(ctx, userID, workspaceID, repositoryID, repositories.GrantReader)
	if err != nil {
		return OpenedFile{}, err
	}
	if !granted {
		return OpenedFile{}, repositories.ErrForbidden
	}

	file, err := s.readPublishedFile(ctx, workspaceID, repositoryID, fileID)
	if err != nil {
		return OpenedFile{}, err
	}
	return s.openObject(ctx, workspaceID, file, offset, length)
}

func (s *Service) IssueDownloadTicket(
	ctx context.Context,
	userID string,
	workspaceID string,
	repositoryID string,
	artifactVersionID string,
	fileID string,
	ttl time.Duration,
) (DownloadTicket, error) {
	if s == nil || ctx == nil {
		return DownloadTicket{}, errors.New("artifact download service is unavailable")
	}
	userID, err := parseID(userID, repositories.ErrUnauthenticated)
	if err != nil {
		return DownloadTicket{}, repositories.ErrUnauthenticated
	}
	workspaceID, err = parseID(workspaceID, repositories.ErrInvalidWorkspaceID)
	if err != nil {
		return DownloadTicket{}, repositories.ErrInvalidWorkspaceID
	}
	repositoryID, err = parseID(repositoryID, repositories.ErrInvalidRepositoryID)
	if err != nil {
		return DownloadTicket{}, repositories.ErrInvalidRepositoryID
	}
	artifactVersionID, err = parseID(artifactVersionID, ErrArtifactNotFound)
	if err != nil {
		return DownloadTicket{}, ErrArtifactNotFound
	}
	fileID, err = parseID(fileID, ErrArtifactNotFound)
	if err != nil {
		return DownloadTicket{}, ErrArtifactNotFound
	}
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	if ttl < time.Minute || ttl > 15*time.Minute {
		return DownloadTicket{}, errors.New("download ticket lifetime must be between 1 and 15 minutes")
	}

	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		return DownloadTicket{}, errors.New("download ticket could not be generated")
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	clear(rawToken)
	digest := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(digest[:])
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	ticket := DownloadTicket{Token: token, ExpiresAt: expiresAt}
	err = s.repositories.WithRepositoryGrantTransaction(
		ctx, userID, workspaceID, repositoryID, repositories.GrantReader,
		func(tx *sql.Tx) error {
			var createdAt string
			query := `SELECT files.artifact_file_id, files.path, files.content_type, files.size_bytes,
				files.sha256, files.created_by, files.created_at
				FROM registry_generic_artifact_files AS files
				JOIN registry_generic_artifact_versions AS versions
					ON versions.artifact_version_id = files.artifact_version_id
					AND versions.workspace_id = files.workspace_id AND versions.repository_id = files.repository_id
				WHERE files.artifact_file_id = ` + bind(s.driver, 1) + `
					AND files.artifact_version_id = ` + bind(s.driver, 2) + `
					AND files.workspace_id = ` + bind(s.driver, 3) + ` AND files.repository_id = ` + bind(s.driver, 4) + `
					AND versions.status = 'published'`
			if err := tx.QueryRowContext(ctx, query, fileID, artifactVersionID, workspaceID, repositoryID).Scan(
				&ticket.File.ID, &ticket.File.Path, &ticket.File.ContentType, &ticket.File.Size,
				&ticket.File.SHA256, &ticket.File.CreatedBy, &createdAt); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrArtifactNotFound
				}
				return errors.New("published artifact file could not be read")
			}
			ticket.File.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
			if err != nil || ticket.File.Size < 0 || !sha256Pattern.MatchString(ticket.File.SHA256) {
				return ErrArtifactIntegrity
			}
			query = `INSERT INTO registry_generic_download_tickets
				(token_sha256, artifact_file_id, issued_by, issued_at, expires_at)
				VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `)`
			if _, err := tx.ExecContext(ctx, query, tokenHash, fileID, userID,
				now.Format(time.RFC3339Nano), expiresAt.Format(time.RFC3339Nano)); err != nil {
				return errors.New("download ticket could not be recorded")
			}
			return nil
		},
	)
	if err != nil {
		return DownloadTicket{}, err
	}
	return ticket, nil
}

// ResolveDownloadTicket returns file metadata scoped to a short-lived bearer
// capability. The issuer's current grant is deliberately not rechecked here;
// the link remains usable until expiry or repository deactivation.
func (s *Service) ResolveDownloadTicket(ctx context.Context, token string) (File, time.Time, error) {
	if s == nil || ctx == nil {
		return File{}, time.Time{}, errors.New("artifact download service is unavailable")
	}
	tokenHash, err := hashDownloadToken(token)
	if err != nil {
		return File{}, time.Time{}, ErrDownloadTicketUnavailable
	}
	query := `SELECT files.artifact_file_id, files.path, files.content_type, files.size_bytes,
		files.sha256, files.created_by, files.created_at, tickets.expires_at
		FROM registry_generic_download_tickets AS tickets
		JOIN registry_generic_artifact_files AS files ON files.artifact_file_id = tickets.artifact_file_id
		JOIN registry_generic_artifact_versions AS versions
			ON versions.artifact_version_id = files.artifact_version_id
			AND versions.workspace_id = files.workspace_id AND versions.repository_id = files.repository_id
		JOIN registry_repositories AS repositories
			ON repositories.repository_id = files.repository_id AND repositories.workspace_id = files.workspace_id
		JOIN registry_workspaces AS workspaces ON workspaces.workspace_id = files.workspace_id
		WHERE tickets.token_sha256 = ` + bind(s.driver, 1) + ` AND tickets.revoked_at IS NULL
			AND versions.status = 'published' AND repositories.status = 'active' AND workspaces.status = 'active'`
	var file File
	var createdAt string
	var expiresAt string
	if err := s.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&file.ID, &file.Path, &file.ContentType, &file.Size, &file.SHA256, &file.CreatedBy, &createdAt, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return File{}, time.Time{}, ErrDownloadTicketUnavailable
		}
		return File{}, time.Time{}, errors.New("download ticket could not be resolved")
	}
	file.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil || file.Size < 0 || !sha256Pattern.MatchString(file.SHA256) {
		return File{}, time.Time{}, ErrArtifactIntegrity
	}
	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return File{}, time.Time{}, errors.New("download ticket expiry is invalid")
	}
	if !time.Now().UTC().Before(expiry) {
		return File{}, time.Time{}, ErrDownloadTicketUnavailable
	}
	return file, expiry, nil
}

func (s *Service) OpenDownloadTicket(
	ctx context.Context,
	token string,
	offset int64,
	length int64,
) (OpenedFile, time.Time, error) {
	if s == nil || ctx == nil {
		return OpenedFile{}, time.Time{}, errors.New("artifact download service is unavailable")
	}
	tokenHash, err := hashDownloadToken(token)
	if err != nil {
		return OpenedFile{}, time.Time{}, ErrDownloadTicketUnavailable
	}
	query := `SELECT files.artifact_file_id, files.path, files.content_type, files.size_bytes,
		files.sha256, files.created_by, files.created_at, files.workspace_id, tickets.expires_at
		FROM registry_generic_download_tickets AS tickets
		JOIN registry_generic_artifact_files AS files ON files.artifact_file_id = tickets.artifact_file_id
		JOIN registry_generic_artifact_versions AS versions
			ON versions.artifact_version_id = files.artifact_version_id
			AND versions.workspace_id = files.workspace_id AND versions.repository_id = files.repository_id
		JOIN registry_repositories AS repositories
			ON repositories.repository_id = files.repository_id AND repositories.workspace_id = files.workspace_id
		JOIN registry_workspaces AS workspaces ON workspaces.workspace_id = files.workspace_id
		WHERE tickets.token_sha256 = ` + bind(s.driver, 1) + ` AND tickets.revoked_at IS NULL
			AND versions.status = 'published' AND repositories.status = 'active' AND workspaces.status = 'active'`
	var file File
	var workspaceID string
	var createdAt string
	var expiresAt string
	if err := s.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&file.ID, &file.Path, &file.ContentType, &file.Size, &file.SHA256,
		&file.CreatedBy, &createdAt, &workspaceID, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OpenedFile{}, time.Time{}, ErrDownloadTicketUnavailable
		}
		return OpenedFile{}, time.Time{}, errors.New("download ticket could not be resolved")
	}
	file.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil || file.Size < 0 || !sha256Pattern.MatchString(file.SHA256) {
		return OpenedFile{}, time.Time{}, ErrArtifactIntegrity
	}
	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return OpenedFile{}, time.Time{}, errors.New("download ticket expiry is invalid")
	}
	if !time.Now().UTC().Before(expiry) {
		return OpenedFile{}, time.Time{}, ErrDownloadTicketUnavailable
	}
	opened, err := s.openObject(ctx, workspaceID, file, offset, length)
	if err != nil {
		return OpenedFile{}, time.Time{}, err
	}
	return opened, expiry, nil
}

func hashDownloadToken(token string) (string, error) {
	if len(token) != 43 {
		return "", ErrDownloadTicketUnavailable
	}
	tokenBytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(tokenBytes) != 32 {
		return "", ErrDownloadTicketUnavailable
	}
	digest := sha256.Sum256([]byte(token))
	clear(tokenBytes)
	return hex.EncodeToString(digest[:]), nil
}

func (s *Service) openObject(ctx context.Context, workspaceID string, file File, offset int64, length int64) (OpenedFile, error) {
	if offset < 0 || length < 0 || offset > file.Size || length > file.Size-offset {
		return OpenedFile{}, ErrInvalidRange
	}
	key, err := storage.NewObjectKey(workspaceID, file.SHA256)
	if err != nil {
		return OpenedFile{}, ErrArtifactIntegrity
	}
	var reader io.ReadCloser
	var info storage.ObjectInfo
	if offset == 0 && length == file.Size {
		reader, info, err = s.storage.Open(ctx, key)
	} else {
		reader, info, err = s.storage.OpenRange(ctx, key, offset, length)
	}
	if err != nil {
		return OpenedFile{}, err
	}
	if info.Size != file.Size || info.Key != key {
		_ = reader.Close()
		return OpenedFile{}, ErrArtifactIntegrity
	}
	return OpenedFile{File: file, Reader: reader, Range: offset != 0 || length != file.Size}, nil
}

func (s *Service) GetPublishedVersion(
	ctx context.Context,
	userID string,
	workspaceID string,
	repositoryID string,
	artifactVersionID string,
) (ArtifactVersion, error) {
	if s == nil || ctx == nil {
		return ArtifactVersion{}, errors.New("artifact query service is unavailable")
	}
	userID, err := parseID(userID, repositories.ErrUnauthenticated)
	if err != nil {
		return ArtifactVersion{}, repositories.ErrUnauthenticated
	}
	workspaceID, err = parseID(workspaceID, repositories.ErrInvalidWorkspaceID)
	if err != nil {
		return ArtifactVersion{}, repositories.ErrInvalidWorkspaceID
	}
	repositoryID, err = parseID(repositoryID, repositories.ErrInvalidRepositoryID)
	if err != nil {
		return ArtifactVersion{}, repositories.ErrInvalidRepositoryID
	}
	artifactVersionID, err = parseID(artifactVersionID, ErrArtifactNotFound)
	if err != nil {
		return ArtifactVersion{}, ErrArtifactNotFound
	}
	granted, err := s.repositories.HasRepositoryGrant(ctx, userID, workspaceID, repositoryID, repositories.GrantReader)
	if err != nil {
		return ArtifactVersion{}, err
	}
	if !granted {
		return ArtifactVersion{}, repositories.ErrForbidden
	}

	query := `SELECT collection_name, version_label, created_by, created_at, published_at
		FROM registry_generic_artifact_versions
		WHERE artifact_version_id = ` + bind(s.driver, 1) + ` AND workspace_id = ` + bind(s.driver, 2) +
		` AND repository_id = ` + bind(s.driver, 3) + ` AND status = 'published'`
	var artifact ArtifactVersion
	var createdAt string
	var publishedAt string
	if err := s.db.QueryRowContext(ctx, query, artifactVersionID, workspaceID, repositoryID).Scan(
		&artifact.Collection, &artifact.Version, &artifact.CreatedBy, &createdAt, &publishedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ArtifactVersion{}, ErrArtifactNotFound
		}
		return ArtifactVersion{}, errors.New("published artifact version could not be read")
	}
	artifact.ID = artifactVersionID
	artifact.WorkspaceID = workspaceID
	artifact.RepositoryID = repositoryID
	artifact.Status = "published"
	artifact.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return ArtifactVersion{}, errors.New("artifact creation time is invalid")
	}
	publishedTime, err := time.Parse(time.RFC3339Nano, publishedAt)
	if err != nil {
		return ArtifactVersion{}, errors.New("artifact publication time is invalid")
	}
	artifact.PublishedAt = &publishedTime
	artifact.Files, err = s.loadFilesDB(ctx, artifactVersionID)
	if err != nil {
		return ArtifactVersion{}, err
	}
	return artifact, nil
}

func validateStartUploadRequest(request StartUploadRequest, maxUploadBytes int64) (StartUploadRequest, error) {
	request.Collection = strings.TrimSpace(request.Collection)
	if !collectionNamePattern.MatchString(request.Collection) {
		return StartUploadRequest{}, ErrInvalidCollectionName
	}
	request.Version = strings.TrimSpace(request.Version)
	if !versionLabelPattern.MatchString(request.Version) {
		return StartUploadRequest{}, ErrInvalidVersionLabel
	}
	request.Path = strings.TrimSpace(request.Path)
	if err := validateArtifactPath(request.Path); err != nil {
		return StartUploadRequest{}, err
	}
	mediaType, _, err := mime.ParseMediaType(request.ContentType)
	if err != nil || len(mediaType) > 255 {
		return StartUploadRequest{}, ErrInvalidContentType
	}
	request.ContentType = strings.ToLower(mediaType)
	if request.Size < 0 || request.Size > maxUploadBytes || request.Size > SchemaMaxUploadBytes {
		return StartUploadRequest{}, ErrInvalidArtifactSize
	}
	request.SHA256 = strings.ToLower(strings.TrimSpace(request.SHA256))
	if !sha256Pattern.MatchString(request.SHA256) {
		return StartUploadRequest{}, ErrInvalidDigest
	}
	return request, nil
}

func validateArtifactPath(value string) error {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) ||
		!artifactPathPattern.MatchString(value) || strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return ErrInvalidArtifactPath
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == ':' {
			return ErrInvalidArtifactPath
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." || strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return ErrInvalidArtifactPath
		}
		upperSegment := strings.ToUpper(strings.SplitN(segment, ".", 2)[0])
		switch upperSegment {
		case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
			return ErrInvalidArtifactPath
		}
	}
	return nil
}

func (s *Service) findOrCreateVersion(
	ctx context.Context,
	tx *sql.Tx,
	actorID string,
	workspaceID string,
	repositoryID string,
	request StartUploadRequest,
	now time.Time,
) (string, error) {
	query := `SELECT artifact_version_id, status FROM registry_generic_artifact_versions
		WHERE repository_id = ` + bind(s.driver, 1) + ` AND collection_name = ` + bind(s.driver, 2) + `
			AND version_label = ` + bind(s.driver, 3)
	var versionID string
	var status string
	err := tx.QueryRowContext(ctx, query, repositoryID, request.Collection, request.Version).Scan(&versionID, &status)
	if err == nil {
		if status != "receiving" {
			return "", ErrVersionConflict
		}
		return versionID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("artifact version identity could not be checked")
	}
	versionUUID, err := uuid.NewV7()
	if err != nil {
		return "", errors.New("artifact version identity could not be generated")
	}
	createdAt := now.Format(time.RFC3339Nano)
	query = `INSERT INTO registry_generic_artifact_versions
		(artifact_version_id, workspace_id, repository_id, collection_name, version_label, status, created_by, created_at)
		VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `, 'receiving', ` + bind(s.driver, 6) + `, ` + bind(s.driver, 7) + `)`
	if _, err := tx.ExecContext(ctx, query, versionUUID.String(), workspaceID, repositoryID,
		request.Collection, request.Version, actorID, createdAt); err != nil {
		return "", errors.New("artifact version reservation could not be created")
	}
	return versionUUID.String(), nil
}

func (s *Service) pathReserved(ctx context.Context, tx *sql.Tx, versionID string, filePath string) (bool, error) {
	query := `SELECT EXISTS (
		SELECT 1 FROM registry_generic_upload_sessions
		WHERE artifact_version_id = ` + bind(s.driver, 1) + ` AND lower(path) = lower(` + bind(s.driver, 2) + `)
			AND status IN ('receiving', 'uploading', 'uploaded', 'published')
		UNION ALL
		SELECT 1 FROM registry_generic_artifact_files
		WHERE artifact_version_id = ` + bind(s.driver, 3) + ` AND lower(path) = lower(` + bind(s.driver, 4) + `)
	)`
	var exists bool
	if err := tx.QueryRowContext(ctx, query, versionID, filePath, versionID, filePath).Scan(&exists); err != nil {
		return false, errors.New("artifact path availability could not be checked")
	}
	return exists, nil
}

func (s *Service) claimUploadSession(
	ctx context.Context,
	actorID string,
	workspaceID string,
	repositoryID string,
	uploadSessionID string,
	claimID string,
) (UploadSession, bool, error) {
	var session UploadSession
	var expired bool
	err := s.repositories.WithRepositoryGrantTransaction(
		ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher,
		func(tx *sql.Tx) error {
			var createdBy string
			var expiresAt string
			var status string
			query := `SELECT artifact_version_id, workspace_id, repository_id, path,
				content_type, expected_size, expected_sha256, status, created_by, expires_at
				FROM registry_generic_upload_sessions
				WHERE upload_session_id = ` + bind(s.driver, 1) + `
					AND workspace_id = ` + bind(s.driver, 2) + `
					AND repository_id = ` + bind(s.driver, 3)
			if err := tx.QueryRowContext(ctx, query, uploadSessionID, workspaceID, repositoryID).Scan(
				&session.ArtifactVersionID, &session.WorkspaceID, &session.RepositoryID,
				&session.Path, &session.ContentType, &session.ExpectedSize,
				&session.ExpectedSHA256, &status, &createdBy, &expiresAt); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrUploadNotFound
				}
				return errors.New("artifact upload session could not be read")
			}
			if createdBy != actorID {
				return ErrUploadNotFound
			}
			if status != "receiving" && status != "uploading" {
				return ErrUploadStateConflict
			}
			expires, err := time.Parse(time.RFC3339Nano, expiresAt)
			if err != nil {
				return errors.New("artifact upload session expiry is invalid")
			}
			now := time.Now().UTC()
			if !now.Before(expires) {
				update := `UPDATE registry_generic_upload_sessions
					SET status = 'expired', upload_claim_id = NULL, updated_at = ` + bind(s.driver, 1) + `
					WHERE upload_session_id = ` + bind(s.driver, 2) + ` AND status IN ('receiving', 'uploading')`
				result, err := tx.ExecContext(ctx, update, now.Format(time.RFC3339Nano), uploadSessionID)
				if err != nil {
					return errors.New("expired artifact upload session could not be recorded")
				}
				if err := requireSingleUploadRow(result); err != nil {
					return errors.New("expired artifact upload result could not be checked")
				}
				expired = true
				return nil
			}
			if status != "receiving" {
				return ErrUploadStateConflict
			}
			update := `UPDATE registry_generic_upload_sessions
				SET status = 'uploading', upload_claim_id = ` + bind(s.driver, 1) + `, updated_at = ` + bind(s.driver, 2) + `
				WHERE upload_session_id = ` + bind(s.driver, 3) + ` AND status = 'receiving' AND upload_claim_id IS NULL`
			result, err := tx.ExecContext(ctx, update, claimID, now.Format(time.RFC3339Nano), uploadSessionID)
			if err != nil {
				return errors.New("artifact upload session could not be claimed")
			}
			if err := requireSingleUploadRow(result); err != nil {
				return ErrUploadStateConflict
			}
			session.ID = uploadSessionID
			session.Status = "uploading"
			session.ExpiresAt = expires
			return nil
		},
	)
	if err != nil {
		return UploadSession{}, false, err
	}
	return session, expired, nil
}

func (s *Service) restoreUploadClaim(ctx context.Context, uploadSessionID string, claimID string) error {
	var expiresAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT expires_at FROM registry_generic_upload_sessions
		 WHERE upload_session_id = `+bind(s.driver, 1)+` AND status = 'uploading' AND upload_claim_id = `+bind(s.driver, 2),
		uploadSessionID, claimID).Scan(&expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return errors.New("artifact upload claim expiry could not be read")
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return errors.New("artifact upload claim expiry is invalid")
	}
	now := time.Now().UTC()
	nextStatus := "receiving"
	if !now.Before(expires) {
		nextStatus = "expired"
	}
	update := `UPDATE registry_generic_upload_sessions
		SET status = ` + bind(s.driver, 1) + `, upload_claim_id = NULL, updated_at = ` + bind(s.driver, 2) + `
		WHERE upload_session_id = ` + bind(s.driver, 3) + ` AND status = 'uploading'
			AND upload_claim_id = ` + bind(s.driver, 4) + ` AND expires_at = ` + bind(s.driver, 5)
	result, err := s.db.ExecContext(ctx, update, nextStatus, now.Format(time.RFC3339Nano), uploadSessionID, claimID, expiresAt)
	if err != nil {
		return errors.New("artifact upload claim could not be restored")
	}
	if _, err := result.RowsAffected(); err != nil {
		return errors.New("artifact upload claim restoration result could not be checked")
	}
	return nil
}

func (s *Service) markUploadRejected(
	ctx context.Context,
	uploadSessionID string,
	claimID string,
	objectSHA256 string,
	objectSize int64,
) error {
	query := `UPDATE registry_generic_upload_sessions
		SET status = 'rejected', object_sha256 = ` + bind(s.driver, 1) + `, object_size = ` + bind(s.driver, 2) +
		`, upload_claim_id = NULL, updated_at = ` + bind(s.driver, 3) + `
		WHERE upload_session_id = ` + bind(s.driver, 4) + ` AND status = 'uploading' AND upload_claim_id = ` + bind(s.driver, 5)
	result, err := s.db.ExecContext(ctx, query, objectSHA256, objectSize,
		time.Now().UTC().Format(time.RFC3339Nano), uploadSessionID, claimID)
	if err != nil {
		return errors.New("rejected artifact upload could not be recorded")
	}
	return requireSingleUploadRow(result)
}

func requireSingleUploadRow(result sql.Result) error {
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected != 1 {
		return errors.New("artifact upload state transition did not affect exactly one row")
	}
	return nil
}

func (s *Service) expireOldSessions(ctx context.Context, tx *sql.Tx, artifactVersionID string, now time.Time) error {
	query := `SELECT upload_session_id, expires_at FROM registry_generic_upload_sessions
		WHERE artifact_version_id = ` + bind(s.driver, 1) + ` AND status IN ('receiving', 'uploading')`
	rows, err := tx.QueryContext(ctx, query, artifactVersionID)
	if err != nil {
		return errors.New("artifact upload expirations could not be read")
	}
	var expiredIDs []string
	for rows.Next() {
		var id string
		var expiry string
		if err := rows.Scan(&id, &expiry); err != nil {
			_ = rows.Close()
			return errors.New("artifact upload expiry could not be read")
		}
		parsed, err := time.Parse(time.RFC3339Nano, expiry)
		if err != nil {
			_ = rows.Close()
			return errors.New("artifact upload expiry is invalid")
		}
		if !now.Before(parsed) {
			expiredIDs = append(expiredIDs, id)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return errors.New("artifact upload expiry iteration failed")
	}
	if err := rows.Close(); err != nil {
		return errors.New("artifact upload expiry rows could not be closed")
	}
	for _, id := range expiredIDs {
		update := `UPDATE registry_generic_upload_sessions SET status = 'expired', upload_claim_id = NULL, updated_at = ` + bind(s.driver, 1) +
			` WHERE upload_session_id = ` + bind(s.driver, 2) + ` AND status IN ('receiving', 'uploading')`
		result, err := tx.ExecContext(ctx, update, now.Format(time.RFC3339Nano), id)
		if err != nil {
			return errors.New("expired artifact upload could not be recorded")
		}
		if _, err := result.RowsAffected(); err != nil {
			return errors.New("expired artifact upload result could not be checked")
		}
	}
	return nil
}

func (s *Service) loadUploadedSessions(ctx context.Context, tx *sql.Tx, versionID string) ([]File, error) {
	query := `SELECT path, content_type, object_size, object_sha256
		FROM registry_generic_upload_sessions
		WHERE artifact_version_id = ` + bind(s.driver, 1) + ` AND status = 'uploaded'
		ORDER BY path`
	rows, err := tx.QueryContext(ctx, query, versionID)
	if err != nil {
		return nil, errors.New("uploaded artifact files could not be read")
	}
	defer rows.Close()
	files := make([]File, 0)
	for rows.Next() {
		var file File
		if err := rows.Scan(&file.Path, &file.ContentType, &file.Size, &file.SHA256); err != nil {
			return nil, errors.New("uploaded artifact file record is invalid")
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("uploaded artifact file iteration failed")
	}
	return files, nil
}

func (s *Service) loadFiles(ctx context.Context, tx *sql.Tx, versionID string) ([]File, error) {
	query := `SELECT artifact_file_id, path, content_type, size_bytes, sha256, created_by, created_at
		FROM registry_generic_artifact_files WHERE artifact_version_id = ` + bind(s.driver, 1) + ` ORDER BY path`
	rows, err := tx.QueryContext(ctx, query, versionID)
	if err != nil {
		return nil, errors.New("published artifact files could not be read")
	}
	defer rows.Close()
	files := make([]File, 0)
	for rows.Next() {
		file, err := scanFile(rows)
		if err != nil {
			return nil, errors.New("published artifact file record is invalid")
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("published artifact file iteration failed")
	}
	return files, nil
}

func (s *Service) loadFilesDB(ctx context.Context, versionID string) ([]File, error) {
	query := `SELECT artifact_file_id, path, content_type, size_bytes, sha256, created_by, created_at
		FROM registry_generic_artifact_files WHERE artifact_version_id = ` + bind(s.driver, 1) + ` ORDER BY path`
	rows, err := s.db.QueryContext(ctx, query, versionID)
	if err != nil {
		return nil, errors.New("published artifact files could not be read")
	}
	defer rows.Close()
	files := make([]File, 0)
	for rows.Next() {
		file, err := scanFile(rows)
		if err != nil {
			return nil, errors.New("published artifact file record is invalid")
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("published artifact file iteration failed")
	}
	return files, nil
}

func (s *Service) readPublishedFile(ctx context.Context, workspaceID string, repositoryID string, fileID string) (File, error) {
	query := `SELECT files.artifact_file_id, files.path, files.content_type, files.size_bytes,
		files.sha256, files.created_by, files.created_at
		FROM registry_generic_artifact_files AS files
		JOIN registry_generic_artifact_versions AS versions
			ON versions.artifact_version_id = files.artifact_version_id
			AND versions.workspace_id = files.workspace_id AND versions.repository_id = files.repository_id
		WHERE files.artifact_file_id = ` + bind(s.driver, 1) + `
			AND files.workspace_id = ` + bind(s.driver, 2) + ` AND files.repository_id = ` + bind(s.driver, 3) + `
			AND versions.status = 'published'`
	var file File
	var createdAt string
	if err := s.db.QueryRowContext(ctx, query, fileID, workspaceID, repositoryID).Scan(
		&file.ID, &file.Path, &file.ContentType, &file.Size, &file.SHA256, &file.CreatedBy, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return File{}, ErrArtifactNotFound
		}
		return File{}, errors.New("published artifact file could not be read")
	}
	if file.Size < 0 || !sha256Pattern.MatchString(file.SHA256) {
		return File{}, ErrArtifactIntegrity
	}
	created, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return File{}, errors.New("artifact file creation time is invalid")
	}
	file.CreatedAt = created
	return file, nil
}

type scanner interface {
	Scan(...any) error
}

func scanFile(row scanner) (File, error) {
	var file File
	var createdAt string
	if err := row.Scan(&file.ID, &file.Path, &file.ContentType, &file.Size, &file.SHA256, &file.CreatedBy, &createdAt); err != nil {
		return File{}, err
	}
	created, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return File{}, err
	}
	file.CreatedAt = created
	if file.Size < 0 || !sha256Pattern.MatchString(file.SHA256) {
		return File{}, ErrArtifactIntegrity
	}
	return file, nil
}

func recordAudit(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, actorID string, action string, targetType string, targetID string) error {
	eventID, err := uuid.NewV7()
	if err != nil {
		return errors.New("artifact audit event identity could not be generated")
	}
	query := `INSERT INTO registry_audit_events
		(event_id, actor_user_id, action, target_type, target_id, outcome, occurred_at)
		VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, ` + bind(driver, 3) + `, ` + bind(driver, 4) + `, ` + bind(driver, 5) + `, 'succeeded', ` + bind(driver, 6) + `)`
	if _, err := tx.ExecContext(ctx, query, eventID.String(), actorID, action, targetType, targetID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return errors.New("artifact audit event could not be recorded")
	}
	return nil
}

func parseID(value string, invalid error) (string, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil {
		return "", invalid
	}
	return parsed.String(), nil
}

func bind(driver config.DatabaseDriver, position int) string {
	if driver == config.Postgres {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}

func (s *Service) maxBytes() int64 {
	return s.maxUploadBytes
}
