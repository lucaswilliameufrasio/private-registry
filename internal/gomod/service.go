package gomod

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
	"time"

	"github.com/google/uuid"
	modulezip "golang.org/x/mod/zip"
	"private-registry/internal/config"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

var (
	ErrInvalidPublication = errors.New("Go module publication is invalid")
	ErrVersionExists      = errors.New("Go module version already exists")
	ErrModuleUnavailable  = errors.New("Go module is unavailable")
	ErrCapacity           = errors.New("Go module upload capacity is temporarily unavailable")
	ErrQuotaUnavailable   = errors.New("Go module publication is unavailable while logical quotas are configured")
)

// Service owns Go module version publication and retrieval. Storage and SQL
// cannot be committed atomically; a rejected or failed publication can leave an
// unreferenced object, which requires separately coordinated garbage collection.
type Service struct {
	db           *sql.DB
	driver       config.DatabaseDriver
	repositories *repositories.Service
	objects      storage.Driver
	staging      string
	maxZip       int64
	maxFiles     int
	slots        chan struct{}
}

type Options struct {
	StagingDirectory string
	MaxZipBytes      int64
	MaxFiles         int
	MaxConcurrent    int
}

func NewService(db *sql.DB, driver config.DatabaseDriver, repositoryService *repositories.Service, objects storage.Driver, options Options) (*Service, error) {
	if db == nil || repositoryService == nil || objects == nil || (driver != config.SQLite && driver != config.Postgres) || !filepath.IsAbs(options.StagingDirectory) || options.MaxZipBytes < 1 || options.MaxZipBytes > modulezip.MaxZipFile || options.MaxFiles < 1 || options.MaxFiles > 100000 || options.MaxConcurrent < 1 || options.MaxConcurrent > 128 {
		return nil, errors.New("Go module service configuration is invalid")
	}
	info, err := os.Lstat(options.StagingDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Go module staging must be an existing private directory")
	}
	return &Service{db: db, driver: driver, repositories: repositoryService, objects: objects, staging: options.StagingDirectory, maxZip: options.MaxZipBytes, maxFiles: options.MaxFiles, slots: make(chan struct{}, options.MaxConcurrent)}, nil
}

func (s *Service) bind(n int) string {
	if s.driver == config.Postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func (s *Service) MaxZipBytes() int64 {
	if s == nil {
		return 0
	}
	return s.maxZip
}

func canonicalID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// Publish receives a complete archive into private bounded staging, validates
// it, stores it and revalidates the publisher grant in the catalog transaction.
// This experimental method must not be exposed before quota reservations and
// repository review are implemented. Configured quotas fail closed.
func (s *Service) Publish(ctx context.Context, actorID, workspaceID, repositoryID, modulePath, version string, sourceTime time.Time, modBytes []byte, archive io.Reader) (retErr error) {
	if s == nil || ctx == nil || archive == nil || !canonicalID(actorID) || !canonicalID(workspaceID) || !canonicalID(repositoryID) || len(modulePath) > 1024 || len(version) > 200 {
		return ErrInvalidPublication
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrInvalidPublication
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := NewVersionInfo(modulePath, version, sourceTime)
	if err != nil || len(modBytes) == 0 || len(modBytes) > modulezip.MaxGoMod {
		return ErrInvalidPublication
	}
	modBytes = bytes.Clone(modBytes)
	allowed, err := s.repositories.HasRepositoryGrant(ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher)
	if err != nil {
		return err
	}
	if !allowed {
		return repositories.ErrForbidden
	}
	if err := repositories.RequireFormat(ctx, s.db, s.driver, workspaceID, repositoryID, repositories.FormatGo); err != nil {
		return err
	}
	if err := s.requireUnconfiguredQuota(ctx, s.db, workspaceID, repositoryID); err != nil {
		return err
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return ErrCapacity
	}
	stage, err := os.CreateTemp(s.staging, "go-module-*")
	if err != nil {
		return errors.New("Go module staging could not be created")
	}
	stagePath := stage.Name()
	defer func() {
		if err := os.Remove(stagePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, errors.New("Go module staging could not be removed"))
		}
	}()
	hash := sha256.New()
	limited := &io.LimitedReader{R: &contextReader{ctx: ctx, source: archive}, N: s.maxZip + 1}
	size, copyErr := io.Copy(io.MultiWriter(stage, hash), limited)
	if copyErr == nil && (size < 1 || size > s.maxZip) {
		copyErr = ErrInvalidPublication
	}
	if copyErr == nil {
		copyErr = stage.Sync()
	}
	closeErr := stage.Close()
	if copyErr != nil || closeErr != nil {
		return errors.New("Go module archive could not be staged")
	}
	if err := ValidatePublication(ctx, modulePath, version, modBytes, stagePath, s.maxFiles); err != nil {
		return ErrInvalidPublication
	}
	file, err := os.Open(stagePath)
	if err != nil {
		return errors.New("Go module archive could not be opened")
	}
	stored, putErr := s.objects.Put(ctx, workspaceID, file, size)
	closeErr = file.Close()
	if putErr != nil || closeErr != nil {
		return errors.New("Go module archive could not be stored")
	}
	key, err := storage.NewObjectKey(workspaceID, hex.EncodeToString(hash.Sum(nil)))
	if err != nil || stored.Key != key || stored.Size != size {
		return errors.New("stored Go module archive metadata is invalid")
	}
	storedReader, readInfo, err := s.objects.Open(ctx, key)
	if err != nil || storedReader == nil {
		if storedReader != nil {
			_ = storedReader.Close()
		}
		return errors.New("stored Go module archive could not be verified")
	}
	storedHash := sha256.New()
	readSize, readErr := io.Copy(storedHash, &io.LimitedReader{R: &contextReader{ctx: ctx, source: storedReader}, N: size + 1})
	readCloseErr := storedReader.Close()
	if readErr != nil || readCloseErr != nil || readInfo.Key != key || readInfo.Size != size || readSize != size || hex.EncodeToString(storedHash.Sum(nil)) != key.SHA256 {
		return errors.New("stored Go module archive failed verification")
	}
	return s.repositories.WithRepositoryGrantTransaction(ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher, func(tx *sql.Tx) error {
		if err := repositories.RequireFormat(ctx, tx, s.driver, workspaceID, repositoryID, repositories.FormatGo); err != nil {
			return err
		}
		if err := repositories.RequireGoPrivateNamespace(ctx, tx, s.driver, workspaceID, repositoryID, modulePath); err != nil {
			return err
		}
		if err := repositories.RequireNoReview(ctx, tx, s.driver, workspaceID, repositoryID); err != nil {
			return err
		}
		if err := s.requireUnconfiguredQuota(ctx, tx, workspaceID, repositoryID); err != nil {
			return err
		}
		var reserved bool
		query := `SELECT EXISTS (SELECT 1 FROM registry_go_upload_sessions WHERE repository_id = ` + s.bind(1) + ` AND module_path = ` + s.bind(2) + ` AND version = ` + s.bind(3) + ` AND status IN ('receiving', 'uploading', 'uploaded'))`
		if err := tx.QueryRowContext(ctx, query, repositoryID, modulePath, version).Scan(&reserved); err != nil {
			return errors.New("Go upload reservation could not be checked")
		}
		if reserved {
			return ErrReservationConflict
		}
		id, err := uuid.NewV7()
		if err != nil {
			return errors.New("Go module version identity could not be generated")
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		query = `INSERT INTO registry_go_module_versions (module_version_id, workspace_id, repository_id, module_path, version, mod_bytes, zip_sha256, zip_size, source_time, created_by, created_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `, ` + s.bind(7) + `, ` + s.bind(8) + `, ` + s.bind(9) + `, ` + s.bind(10) + `, ` + s.bind(11) + `) ON CONFLICT (repository_id, module_path, version) DO NOTHING`
		result, err := tx.ExecContext(ctx, query, id.String(), workspaceID, repositoryID, modulePath, version, modBytes, key.SHA256, size, info.Time.Format(time.RFC3339Nano), actorID, now)
		if err != nil {
			return errors.New("Go module version could not be recorded")
		}
		count, err := result.RowsAffected()
		if err != nil {
			return errors.New("Go module version result could not be checked")
		}
		if count != 1 {
			query := `SELECT mod_bytes, zip_sha256, zip_size, source_time, created_by FROM registry_go_module_versions WHERE workspace_id = ` + s.bind(1) + ` AND repository_id = ` + s.bind(2) + ` AND module_path = ` + s.bind(3) + ` AND version = ` + s.bind(4)
			var existingMod []byte
			var existingDigest, existingTime, existingActor string
			var existingSize int64
			if err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID, modulePath, version).Scan(&existingMod, &existingDigest, &existingSize, &existingTime, &existingActor); err != nil {
				return errors.New("existing Go module version could not be checked")
			}
			if existingActor == actorID && existingDigest == key.SHA256 && existingSize == size && existingTime == info.Time.Format(time.RFC3339Nano) && bytes.Equal(existingMod, modBytes) {
				return nil
			}
			return ErrVersionExists
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Go module audit identity could not be generated")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'go.module.published', 'go_module_version', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), actorID, id.String(), now); err != nil {
			return errors.New("Go module publication could not be audited")
		}
		return nil
	})
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

// This is a temporary fail-closed boundary, not quota reservation or usage
// accounting. The transaction-time check catches changes during the upload.
func (s *Service) requireUnconfiguredQuota(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, workspaceID, repositoryID string) error {
	query := `SELECT w.logical_quota_bytes, r.logical_quota_bytes FROM registry_workspaces w JOIN registry_repositories r ON r.workspace_id = w.workspace_id WHERE w.workspace_id = ` + s.bind(1) + ` AND r.repository_id = ` + s.bind(2)
	var workspaceLimit, repositoryLimit sql.NullInt64
	if err := queryer.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&workspaceLimit, &repositoryLimit); err != nil {
		return errors.New("Go module quota policy could not be checked")
	}
	if workspaceLimit.Valid || repositoryLimit.Valid {
		return ErrQuotaUnavailable
	}
	return nil
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}
