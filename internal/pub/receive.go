package pub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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

type ReceiptInput struct {
	Name     string
	Version  string
	Manifest []byte
	Size     int64
}

var ErrReceiptCapacity = errors.New("pub receipt capacity is temporarily unavailable")

type ReceiptOptions struct {
	StagingDirectory string
	Limits           ArchiveLimits
	MaxConcurrent    int
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
	if db == nil || repos == nil || objects == nil || (driver != config.SQLite && driver != config.Postgres) || !filepath.IsAbs(options.StagingDirectory) || options.MaxConcurrent < 1 || options.MaxConcurrent > 128 || options.Limits.MaxCompressedBytes < 1 || options.Limits.MaxCompressedBytes > 64<<20 || options.Limits.MaxUncompressedBytes < 1 || options.Limits.MaxUncompressedBytes > 1<<30 || options.Limits.MaxEntries < 1 || options.Limits.MaxEntries > 100000 || options.Limits.MaxManifestBytes < 1 || options.Limits.MaxManifestBytes > 16<<20 {
		return nil, errors.New("pub receipt service configuration is invalid")
	}
	info, err := os.Lstat(options.StagingDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("pub receipt staging must be an existing private directory")
	}
	return &ReceiptService{db: db, repositories: repos, driver: driver, objects: objects, options: options, slots: make(chan struct{}, options.MaxConcurrent)}, nil
}

func (s *ReceiptService) bind(n int) string {
	if s.driver == config.Postgres {
		return "$" + strconv.Itoa(n)
	}
	return "?"
}

// Receive claims an authorized reservation, validates and stores the tarball,
// verifies readback, and reauthorizes before recording an immutable receipt.
// It does not publish or serve content. The caller must authenticate before
// reading the body and bound transport and aggregate staging resources.
func (s *ReceiptService) Receive(ctx context.Context, bearer, workspace, repository, reservationID string, publication ReceiptInput, source io.Reader) (retErr error) {
	if s == nil || ctx == nil || source == nil || publication.Size < 1 || publication.Size > s.options.Limits.MaxCompressedBytes || len(publication.Manifest) < 2 || int64(len(publication.Manifest)) > s.options.Limits.MaxManifestBytes {
		return ErrReservationUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrReservationUnavailable
	}
	id, err := uuid.Parse(reservationID)
	if err != nil || id.String() != reservationID {
		return ErrReservationUnavailable
	}
	publication.Manifest = bytes.Clone(publication.Manifest)
	metadataHash := sha256.Sum256(publication.Manifest)
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return ErrReceiptCapacity
	}
	claim, err := uuid.NewV7()
	if err != nil {
		return errors.New("pub receipt claim could not be created")
	}
	var expectedHash string
	err = s.repositories.WithPubWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, _ := strings.Cut(strings.TrimPrefix(bearer, "prpw_"), ".")
		query := `SELECT name, version, tarball_sha256, tarball_size, metadata_sha256, expires_at_ms FROM registry_pub_reservations WHERE reservation_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND token_id = ` + s.bind(4) + ` AND created_by = ` + s.bind(5) + ` AND status = 'reserved' AND recovery_invalidated = 0`
		var name, version, metadata string
		var size, expires int64
		if err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository, tokenID, actor).Scan(&name, &version, &expectedHash, &size, &metadata, &expires); errors.Is(err, sql.ErrNoRows) {
			return ErrReservationUnavailable
		} else if err != nil {
			return errors.New("pub reservation could not be read")
		}
		if name != publication.Name || version != publication.Version || size != publication.Size || metadata != hex.EncodeToString(metadataHash[:]) || expires <= time.Now().UTC().UnixMilli() {
			return ErrReservationUnavailable
		}
		query = `UPDATE registry_pub_reservations SET status = 'uploading', upload_claim_id = ` + s.bind(1) + `, review_hold = CASE WHEN review_hold = 1 OR (SELECT review_required FROM registry_repositories WHERE repository_id = registry_pub_reservations.repository_id AND workspace_id = registry_pub_reservations.workspace_id) = 1 THEN 1 ELSE 0 END WHERE reservation_id = ` + s.bind(2) + ` AND status = 'reserved' AND recovery_invalidated = 0`
		changed, err := tx.ExecContext(ctx, query, claim.String(), reservationID)
		if err != nil {
			return errors.New("pub receipt claim could not be recorded")
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
			query := `UPDATE registry_pub_reservations SET status = 'reserved', upload_claim_id = NULL WHERE reservation_id = ` + s.bind(1) + ` AND status = 'uploading' AND upload_claim_id = ` + s.bind(2)
			if _, err := s.db.ExecContext(ctx, query, reservationID, claim.String()); err != nil {
				retErr = errors.Join(retErr, errors.New("pub receipt claim remains until expiry"))
			}
		}
	}()
	stage, err := os.CreateTemp(s.options.StagingDirectory, "pub-receipt-*")
	if err != nil {
		return errors.New("pub receipt staging could not be created")
	}
	stagePath := stage.Name()
	defer func() {
		if err := os.Remove(stagePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, errors.New("pub receipt staging could not be removed"))
		}
	}()
	hash := sha256.New()
	read, copyErr := io.Copy(io.MultiWriter(stage, hash), &io.LimitedReader{R: &contextReader{ctx: ctx, source: source}, N: publication.Size + 1})
	if copyErr == nil {
		copyErr = stage.Sync()
	}
	closeErr := stage.Close()
	if copyErr != nil || closeErr != nil || read != publication.Size || hex.EncodeToString(hash.Sum(nil)) != expectedHash {
		return errors.New("pub receipt staging failed or differs from reservation")
	}
	file, err := os.Open(stagePath)
	if err != nil {
		return errors.New("pub receipt staging could not be opened")
	}
	contents, validateErr := InspectPackage(ctx, file, publication.Name, publication.Version, s.options.Limits)
	if validateErr == nil && (!bytes.Equal(contents.Manifest, publication.Manifest) || contents.Size != publication.Size || contents.SHA256 != expectedHash) {
		validateErr = errors.New("Pub staged archive differs from reservation")
	}
	closeErr = file.Close()
	if validateErr != nil || closeErr != nil {
		return errors.New("pub staged publication is invalid")
	}
	file, err = os.Open(stagePath)
	if err != nil {
		return errors.New("pub receipt staging could not be reopened")
	}
	stored, putErr := s.objects.Put(ctx, workspace, file, publication.Size)
	closeErr = file.Close()
	key, keyErr := storage.NewObjectKey(workspace, expectedHash)
	if putErr != nil || closeErr != nil || keyErr != nil || stored.Key != key || stored.Size != publication.Size {
		return errors.New("pub tarball could not be stored")
	}
	reader, info, err := s.objects.Open(ctx, key)
	if err != nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		return errors.New("pub tarball readback could not be opened")
	}
	verified := sha256.New()
	read, readErr := io.Copy(verified, &io.LimitedReader{R: &contextReader{ctx: ctx, source: reader}, N: publication.Size + 1})
	closeErr = reader.Close()
	if readErr != nil || closeErr != nil || read != publication.Size || info.Key != key || info.Size != publication.Size || hex.EncodeToString(verified.Sum(nil)) != expectedHash {
		return errors.New("pub tarball readback failed")
	}
	err = s.repositories.WithPubWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, _ := strings.Cut(strings.TrimPrefix(bearer, "prpw_"), ".")
		now := time.Now().UTC()
		query := `UPDATE registry_pub_reservations SET status = 'uploaded', upload_claim_id = NULL, object_verified = 1, manifest = ` + s.bind(1) + `, review_hold = CASE WHEN review_hold = 1 OR (SELECT review_required FROM registry_repositories WHERE repository_id = registry_pub_reservations.repository_id AND workspace_id = registry_pub_reservations.workspace_id) = 1 THEN 1 ELSE 0 END WHERE reservation_id = ` + s.bind(2) + ` AND workspace_id = ` + s.bind(3) + ` AND repository_id = ` + s.bind(4) + ` AND token_id = ` + s.bind(5) + ` AND created_by = ` + s.bind(6) + ` AND status = 'uploading' AND upload_claim_id = ` + s.bind(7) + ` AND recovery_invalidated = 0 AND expires_at_ms > ` + s.bind(8)
		changed, err := tx.ExecContext(ctx, query, string(publication.Manifest), reservationID, workspace, repository, tokenID, actor, claim.String(), now.UnixMilli())
		if err != nil {
			return errors.New("pub verified receipt could not be recorded")
		}
		count, err := changed.RowsAffected()
		if err != nil || count != 1 {
			return ErrReservationUnavailable
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("pub receipt audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'user', 'pub.receipt.verified', 'pub_reservation', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), actor, reservationID, now.Format(time.RFC3339Nano)); err != nil {
			return errors.New("pub receipt could not be audited")
		}
		return nil
	})
	if err != nil {
		return err
	}
	finished = true
	return nil
}
