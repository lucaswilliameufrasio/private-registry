package cargo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

var ErrReceiptCapacity = errors.New("Cargo receipt capacity is temporarily unavailable")

type ReceiptOptions struct {
	StagingDirectory string
	Limits           ArchiveLimits
	MaxConcurrent    int
	CurrentIndex     string
	DefaultIndex     string
}

type ReceiptService struct {
	db           *sql.DB
	repositories *repositories.Service
	driver       config.DatabaseDriver
	objects      storage.Driver
	options      ReceiptOptions
	slots        chan struct{}
}

func NewReceiptService(db *sql.DB, repos *repositories.Service, driver config.DatabaseDriver, objects storage.Driver, options ReceiptOptions) (*ReceiptService, error) {
	if db == nil || repos == nil || objects == nil || (driver != config.SQLite && driver != config.Postgres) || !filepath.IsAbs(options.StagingDirectory) || options.MaxConcurrent < 1 || options.MaxConcurrent > 128 || options.Limits.MaxCompressedBytes < 1 || options.Limits.MaxCompressedBytes > 500<<20 || options.Limits.MaxUncompressedBytes < 1 || options.Limits.MaxFiles < 1 || options.Limits.MaxManifestBytes < 1 || options.CurrentIndex == "" || options.DefaultIndex == "" {
		return nil, errors.New("Cargo receipt service configuration is invalid")
	}
	info, err := os.Lstat(options.StagingDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Cargo receipt staging must be an existing private directory")
	}
	return &ReceiptService{db: db, repositories: repos, driver: driver, objects: objects, options: options, slots: make(chan struct{}, options.MaxConcurrent)}, nil
}

func (s *ReceiptService) bind(n int) string {
	if s.driver == config.Postgres {
		return "$" + strconv.Itoa(n)
	}
	return "?"
}

// Receive claims a reservation, validates and stores its archive, then records
// a verified receipt after reauthorizing. It does not publish or serve content.
// The caller must authenticate before accepting the framed body and must bound
// aggregate staging and transport reads; context cannot stop a blocking reader.
func (s *ReceiptService) Receive(ctx context.Context, bearer, workspace, repository, reservationID string, frame PublishFrame, source io.Reader) (retErr error) {
	if s == nil || ctx == nil || source == nil || frame.Size < 1 || frame.Size > s.options.Limits.MaxCompressedBytes {
		return ErrReservationUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrReservationUnavailable
	}
	id, err := uuid.Parse(reservationID)
	if err != nil || id.String() != reservationID {
		return ErrReservationUnavailable
	}
	frame.Metadata = bytes.Clone(frame.Metadata)
	metadataDigest := sha256.Sum256(frame.Metadata)
	metadataHash := hex.EncodeToString(metadataDigest[:])
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return ErrReceiptCapacity
	}
	claim, err := uuid.NewV7()
	if err != nil {
		return errors.New("Cargo receipt claim could not be created")
	}
	err = s.repositories.WithCargoWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, _ := strings.Cut(strings.TrimPrefix(bearer, "prcw_"), ".")
		query := `SELECT archive_sha256, archive_size, metadata_sha256, expires_at_ms FROM registry_cargo_reservations WHERE reservation_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND token_id = ` + s.bind(4) + ` AND created_by = ` + s.bind(5) + ` AND status = 'reserved' AND recovery_invalidated = 0`
		var digest, metadata string
		var size, expires int64
		if err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository, tokenID, actor).Scan(&digest, &size, &metadata, &expires); errors.Is(err, sql.ErrNoRows) {
			return ErrReservationUnavailable
		} else if err != nil {
			return errors.New("Cargo reservation could not be read")
		}
		if digest != frame.SHA256 || size != frame.Size || metadata != metadataHash || expires <= time.Now().UTC().UnixMilli() {
			return ErrReservationUnavailable
		}
		query = `UPDATE registry_cargo_reservations SET status = 'uploading', upload_claim_id = ` + s.bind(1) + `, review_hold = CASE WHEN review_hold = 1 OR (SELECT review_required FROM registry_repositories WHERE repository_id = registry_cargo_reservations.repository_id AND workspace_id = registry_cargo_reservations.workspace_id) = 1 THEN 1 ELSE 0 END WHERE reservation_id = ` + s.bind(2) + ` AND status = 'reserved' AND recovery_invalidated = 0`
		changed, err := tx.ExecContext(ctx, query, claim.String(), reservationID)
		if err != nil {
			return errors.New("Cargo receipt claim could not be recorded")
		}
		count, err := changed.RowsAffected()
		if err != nil || count != 1 {
			return ErrReservationUnavailable
		}
		return nil
	})
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		if !finished {
			query := `UPDATE registry_cargo_reservations SET status = 'reserved', upload_claim_id = NULL WHERE reservation_id = ` + s.bind(1) + ` AND status = 'uploading' AND upload_claim_id = ` + s.bind(2)
			if _, err := s.db.ExecContext(ctx, query, reservationID, claim.String()); err != nil {
				retErr = errors.Join(retErr, errors.New("Cargo receipt claim remains until expiry"))
			}
		}
	}()
	stage, err := os.CreateTemp(s.options.StagingDirectory, "cargo-receipt-*")
	if err != nil {
		return errors.New("Cargo receipt staging could not be created")
	}
	stagePath := stage.Name()
	defer func() {
		if err := os.Remove(stagePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, errors.New("Cargo receipt staging could not be removed"))
		}
	}()
	hash := sha256.New()
	read, copyErr := io.Copy(io.MultiWriter(stage, hash), &io.LimitedReader{R: &contextReader{ctx: ctx, source: source}, N: frame.Size + 1})
	if copyErr == nil {
		copyErr = stage.Sync()
	}
	closeErr := stage.Close()
	if copyErr != nil || closeErr != nil || read != frame.Size || hex.EncodeToString(hash.Sum(nil)) != frame.SHA256 {
		return errors.New("Cargo receipt staging failed or differs from reservation")
	}
	file, err := os.Open(stagePath)
	if err != nil {
		return errors.New("Cargo receipt staging could not be opened")
	}
	entry, validateErr := ValidateStagedPublication(ctx, frame, file, s.options.Limits, s.options.CurrentIndex, s.options.DefaultIndex)
	closeErr = file.Close()
	if validateErr != nil || closeErr != nil {
		return errors.New("Cargo staged publication is invalid")
	}
	encoded, err := json.Marshal(entry)
	if err != nil || len(encoded) > 16<<20 {
		return errors.New("Cargo index projection could not be encoded")
	}
	file, err = os.Open(stagePath)
	if err != nil {
		return errors.New("Cargo receipt staging could not be reopened")
	}
	stored, putErr := s.objects.Put(ctx, workspace, file, frame.Size)
	closeErr = file.Close()
	key, keyErr := storage.NewObjectKey(workspace, frame.SHA256)
	if putErr != nil || closeErr != nil || keyErr != nil || stored.Key != key || stored.Size != frame.Size {
		return errors.New("Cargo archive could not be stored")
	}
	reader, info, err := s.objects.Open(ctx, key)
	if err != nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		return errors.New("Cargo archive readback could not be opened")
	}
	verified := sha256.New()
	read, readErr := io.Copy(verified, &io.LimitedReader{R: &contextReader{ctx: ctx, source: reader}, N: frame.Size + 1})
	closeErr = reader.Close()
	if readErr != nil || closeErr != nil || read != frame.Size || info.Key != key || info.Size != frame.Size || hex.EncodeToString(verified.Sum(nil)) != frame.SHA256 {
		return errors.New("Cargo archive readback failed")
	}
	err = s.repositories.WithCargoWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		query := `UPDATE registry_cargo_reservations SET status = 'uploaded', object_verified = 1, index_entry = ` + s.bind(1) + `, upload_claim_id = NULL, review_hold = CASE WHEN review_hold = 1 OR (SELECT review_required FROM registry_repositories WHERE repository_id = registry_cargo_reservations.repository_id AND workspace_id = registry_cargo_reservations.workspace_id) = 1 THEN 1 ELSE 0 END WHERE reservation_id = ` + s.bind(2) + ` AND workspace_id = ` + s.bind(3) + ` AND repository_id = ` + s.bind(4) + ` AND created_by = ` + s.bind(5) + ` AND status = 'uploading' AND upload_claim_id = ` + s.bind(6) + ` AND recovery_invalidated = 0 AND expires_at_ms > ` + s.bind(7)
		changed, err := tx.ExecContext(ctx, query, string(encoded), reservationID, workspace, repository, actor, claim.String(), time.Now().UTC().UnixMilli())
		if err != nil {
			return errors.New("Cargo receipt could not be recorded")
		}
		count, err := changed.RowsAffected()
		if err != nil || count != 1 {
			return ErrReservationUnavailable
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Cargo receipt audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'user', 'cargo.receipt.created', 'cargo_reservation', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), actor, reservationID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return errors.New("Cargo receipt could not be audited")
		}
		return nil
	})
	if err != nil {
		return err
	}
	finished = true
	return nil
}
