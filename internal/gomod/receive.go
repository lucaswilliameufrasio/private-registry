package gomod

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

var ErrReservationUnavailable = errors.New("Go upload reservation is unavailable")

// ReceiveReservation claims and validates an upload without publishing it.
// The uploaded state retains the object reference and remains invisible to the
// proxy. Review, rejection, and publication are not yet exposed externally.
func (s *Service) ReceiveReservation(ctx context.Context, actorID, workspaceID, repositoryID, reservationID string, source io.Reader) (retErr error) {
	if s == nil || ctx == nil || source == nil || !canonicalID(actorID) || !canonicalID(workspaceID) || !canonicalID(repositoryID) || !canonicalID(reservationID) {
		return ErrReservationUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrReservationUnavailable
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return ErrCapacity
	}
	claim, err := uuid.NewV7()
	if err != nil {
		return errors.New("Go upload claim could not be created")
	}
	var modulePath, version, digest string
	var mod []byte
	var size, expires int64
	err = s.repositories.WithRepositoryGrantTransaction(ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher, func(tx *sql.Tx) error {
		if err := repositories.RequireFormat(ctx, tx, s.driver, workspaceID, repositoryID, repositories.FormatGo); err != nil {
			return err
		}
		query := `SELECT module_path, version, mod_bytes, zip_sha256, zip_size, expires_at_ms FROM registry_go_upload_sessions WHERE upload_session_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND created_by = ` + s.bind(4) + ` AND status = 'receiving' AND recovery_invalidated = 0`
		if err := tx.QueryRowContext(ctx, query, reservationID, workspaceID, repositoryID, actorID).Scan(&modulePath, &version, &mod, &digest, &size, &expires); errors.Is(err, sql.ErrNoRows) {
			return ErrReservationUnavailable
		} else if err != nil {
			return errors.New("Go upload reservation could not be read")
		}
		if expires <= time.Now().UTC().UnixMilli() {
			return ErrReservationUnavailable
		}
		query = `UPDATE registry_go_upload_sessions SET status = 'uploading', upload_claim_id = ` + s.bind(1) + ` WHERE upload_session_id = ` + s.bind(2) + ` AND status = 'receiving' AND recovery_invalidated = 0`
		result, err := tx.ExecContext(ctx, query, claim.String(), reservationID)
		if err != nil {
			return errors.New("Go upload claim could not be recorded")
		}
		count, err := result.RowsAffected()
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
			query := `UPDATE registry_go_upload_sessions SET status = 'receiving', upload_claim_id = NULL WHERE upload_session_id = ` + s.bind(1) + ` AND status = 'uploading' AND upload_claim_id = ` + s.bind(2)
			if _, err := s.db.ExecContext(ctx, query, reservationID, claim.String()); err != nil {
				retErr = errors.Join(retErr, errors.New("Go upload claim remains until expiry"))
			}
		}
	}()
	stage, err := os.CreateTemp(s.staging, "go-reservation-*")
	if err != nil {
		return errors.New("Go upload staging could not be created")
	}
	path := stage.Name()
	defer func() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, errors.New("Go upload staging could not be removed"))
		}
	}()
	hash := sha256.New()
	read, copyErr := io.Copy(io.MultiWriter(stage, hash), &io.LimitedReader{R: &contextReader{ctx: ctx, source: source}, N: size + 1})
	if copyErr == nil {
		copyErr = stage.Sync()
	}
	closeErr := stage.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(errors.New("Go upload staging failed"), copyErr, closeErr)
	}
	if read != size || hex.EncodeToString(hash.Sum(nil)) != digest {
		return ErrInvalidPublication
	}
	if err := ValidatePublication(ctx, modulePath, version, mod, path, s.maxFiles); err != nil {
		return ErrInvalidPublication
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("Go upload staging could not be opened")
	}
	stored, putErr := s.objects.Put(ctx, workspaceID, file, size)
	closeErr = file.Close()
	key, keyErr := storage.NewObjectKey(workspaceID, digest)
	if putErr != nil || closeErr != nil || keyErr != nil || stored.Key != key || stored.Size != size {
		return errors.New("Go upload could not be stored")
	}
	reader, objectInfo, err := s.objects.Open(ctx, key)
	if err != nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		return errors.New("Go upload readback could not be opened")
	}
	verified := sha256.New()
	read, readErr := io.Copy(verified, &io.LimitedReader{R: &contextReader{ctx: ctx, source: reader}, N: size + 1})
	closeErr = reader.Close()
	if readErr != nil || closeErr != nil || read != size || objectInfo.Key != key || objectInfo.Size != size || hex.EncodeToString(verified.Sum(nil)) != digest {
		return errors.New("Go upload readback failed")
	}
	err = s.repositories.WithRepositoryGrantTransaction(ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher, func(tx *sql.Tx) error {
		query := `UPDATE registry_go_upload_sessions SET status = 'uploaded', object_verified = 1, upload_claim_id = NULL, review_hold = CASE WHEN review_hold = 1 OR (SELECT review_required FROM registry_repositories WHERE repository_id = registry_go_upload_sessions.repository_id AND workspace_id = registry_go_upload_sessions.workspace_id) = 1 THEN 1 ELSE 0 END WHERE upload_session_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND created_by = ` + s.bind(4) + ` AND status = 'uploading' AND upload_claim_id = ` + s.bind(5) + ` AND recovery_invalidated = 0 AND expires_at_ms > ` + s.bind(6)
		result, err := tx.ExecContext(ctx, query, reservationID, workspaceID, repositoryID, actorID, claim.String(), time.Now().UTC().UnixMilli())
		if err != nil {
			return errors.New("Go upload receipt could not be recorded")
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return ErrReservationUnavailable
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Go upload receipt audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'go.upload.received', 'go_upload', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), actorID, reservationID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return errors.New("Go upload receipt could not be audited")
		}
		return nil
	})
	if err != nil {
		return err
	}
	finished = true
	return nil
}
