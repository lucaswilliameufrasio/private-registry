package pub

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/repositories"
)

var ErrNativeUploadUnavailable = errors.New("Pub native upload is unavailable")
var ErrNativeUploadCapacity = errors.New("Pub native upload capacity is exhausted")

// CheckNativeUpload revalidates an unexpired session before a caller reads
// an upload body. It does not consume or bind the session.
func (s *ReservationService) CheckNativeUpload(ctx context.Context, bearer, workspace, repository, uploadID string) error {
	if s == nil || ctx == nil || !canonicalUUID(uploadID) {
		return ErrNativeUploadUnavailable
	}
	return s.repositories.WithPubWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, found := strings.Cut(strings.TrimPrefix(bearer, "prpw_"), ".")
		if !found {
			return repositories.ErrPubWriteTokenUnavailable
		}
		query := `SELECT EXISTS (SELECT 1 FROM registry_pub_native_uploads WHERE upload_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND token_id = ` + s.bind(4) + ` AND created_by = ` + s.bind(5) + ` AND recovery_invalidated = 0 AND expires_at_ms > ` + s.bind(6) + `)`
		var allowed bool
		if err := tx.QueryRowContext(ctx, query, uploadID, workspace, repository, tokenID, actor, time.Now().UTC().UnixMilli()).Scan(&allowed); err != nil {
			return errors.New("Pub native upload could not be checked")
		}
		if !allowed {
			return ErrNativeUploadUnavailable
		}
		return nil
	})
}

// StartNativeUpload creates a bounded, expiring session bound to the exact
// publisher credential. It neither accepts bytes nor publishes anything.
func (s *ReservationService) StartNativeUpload(ctx context.Context, bearer, workspace, repository string) (string, error) {
	if s == nil || ctx == nil {
		return "", ErrNativeUploadUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return "", ErrNativeUploadUnavailable
	}
	var result string
	err := s.repositories.WithPubWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, found := strings.Cut(strings.TrimPrefix(bearer, "prpw_"), ".")
		if !found {
			return repositories.ErrPubWriteTokenUnavailable
		}
		now := time.Now().UTC().Truncate(time.Millisecond)
		query := `SELECT COUNT(*) FROM registry_pub_native_uploads WHERE token_id = ` + s.bind(1) + ` AND reservation_id IS NULL AND recovery_invalidated = 0 AND expires_at_ms > ` + s.bind(2)
		var count int
		if err := tx.QueryRowContext(ctx, query, tokenID, now.UnixMilli()).Scan(&count); err != nil {
			return errors.New("Pub native upload capacity could not be checked")
		}
		if count >= 128 {
			return ErrNativeUploadCapacity
		}
		id, err := uuid.NewV7()
		if err != nil {
			return errors.New("Pub native upload identity could not be created")
		}
		result = id.String()
		query = `INSERT INTO registry_pub_native_uploads (upload_id, workspace_id, repository_id, token_id, created_by, created_at_ms, expires_at_ms) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `, ` + s.bind(7) + `)`
		if _, err := tx.ExecContext(ctx, query, result, workspace, repository, tokenID, actor, now.UnixMilli(), now.Add(30*time.Minute).UnixMilli()); err != nil {
			return errors.New("Pub native upload could not be created")
		}
		return s.audit(ctx, tx, actor, "pub.native_upload.started", result, now)
	})
	if err != nil {
		return "", err
	}
	return result, nil
}

// BindNativeUpload associates a session with a reservation from the same
// actor and original token. Repeating the same binding is idempotent.
func (s *ReservationService) BindNativeUpload(ctx context.Context, bearer, workspace, repository, uploadID, reservationID string) error {
	if s == nil || ctx == nil || !canonicalUUID(uploadID) || !canonicalUUID(reservationID) {
		return ErrNativeUploadUnavailable
	}
	return s.repositories.WithPubWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, found := strings.Cut(strings.TrimPrefix(bearer, "prpw_"), ".")
		if !found {
			return repositories.ErrPubWriteTokenUnavailable
		}
		query := `SELECT reservation_id FROM registry_pub_native_uploads WHERE upload_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND token_id = ` + s.bind(4) + ` AND created_by = ` + s.bind(5) + ` AND recovery_invalidated = 0 AND expires_at_ms > ` + s.bind(6)
		var existing sql.NullString
		if err := tx.QueryRowContext(ctx, query, uploadID, workspace, repository, tokenID, actor, time.Now().UTC().UnixMilli()).Scan(&existing); errors.Is(err, sql.ErrNoRows) {
			return ErrNativeUploadUnavailable
		} else if err != nil {
			return errors.New("Pub native upload could not be checked")
		}
		if existing.Valid {
			if existing.String != reservationID {
				return ErrReservationConflict
			}
			return nil
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_pub_reservations WHERE reservation_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND token_id = ` + s.bind(4) + ` AND created_by = ` + s.bind(5) + ` AND status IN ('reserved', 'uploading', 'uploaded') AND recovery_invalidated = 0)`
		var allowed bool
		if err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository, tokenID, actor).Scan(&allowed); err != nil {
			return errors.New("Pub native upload reservation could not be checked")
		}
		if !allowed {
			return ErrNativeUploadUnavailable
		}
		query = `UPDATE registry_pub_native_uploads SET reservation_id = ` + s.bind(1) + ` WHERE upload_id = ` + s.bind(2) + ` AND reservation_id IS NULL AND recovery_invalidated = 0 AND expires_at_ms > ` + s.bind(3)
		changed, err := tx.ExecContext(ctx, query, reservationID, uploadID, time.Now().UTC().UnixMilli())
		if err != nil {
			return errors.New("Pub native upload could not be bound")
		}
		count, err := changed.RowsAffected()
		if err != nil || count != 1 {
			return ErrNativeUploadUnavailable
		}
		return s.audit(ctx, tx, actor, "pub.native_upload.bound", uploadID, time.Now().UTC())
	})
}

// NativeUploadReservation returns a bound reservation only to the original,
// currently authorized publisher. It does not itself publish the receipt.
func (s *ReservationService) NativeUploadReservation(ctx context.Context, bearer, workspace, repository, uploadID string) (string, error) {
	if s == nil || ctx == nil || !canonicalUUID(uploadID) {
		return "", ErrNativeUploadUnavailable
	}
	var result sql.NullString
	err := s.repositories.WithPubWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, found := strings.Cut(strings.TrimPrefix(bearer, "prpw_"), ".")
		if !found {
			return repositories.ErrPubWriteTokenUnavailable
		}
		query := `SELECT reservation_id FROM registry_pub_native_uploads WHERE upload_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND token_id = ` + s.bind(4) + ` AND created_by = ` + s.bind(5) + ` AND recovery_invalidated = 0 AND expires_at_ms > ` + s.bind(6)
		if err := tx.QueryRowContext(ctx, query, uploadID, workspace, repository, tokenID, actor, time.Now().UTC().UnixMilli()).Scan(&result); errors.Is(err, sql.ErrNoRows) {
			return ErrNativeUploadUnavailable
		} else if err != nil {
			return errors.New("Pub native upload could not be read")
		}
		if !result.Valid || !canonicalUUID(result.String) {
			return ErrNativeUploadUnavailable
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return result.String, nil
}

func canonicalUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// NativeUploadReceived reports whether the bound reservation has a verified
// receipt, after revalidating the session and its original credential.
func (s *ReservationService) NativeUploadReceived(ctx context.Context, bearer, workspace, repository, uploadID, reservationID string) (bool, error) {
	if s == nil || ctx == nil || !canonicalUUID(uploadID) || !canonicalUUID(reservationID) {
		return false, ErrNativeUploadUnavailable
	}
	var received bool
	err := s.repositories.WithPubWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, found := strings.Cut(strings.TrimPrefix(bearer, "prpw_"), ".")
		if !found {
			return repositories.ErrPubWriteTokenUnavailable
		}
		query := `SELECT r.status, r.object_verified FROM registry_pub_native_uploads u JOIN registry_pub_reservations r ON r.reservation_id = u.reservation_id AND r.workspace_id = u.workspace_id AND r.repository_id = u.repository_id AND r.token_id = u.token_id AND r.created_by = u.created_by WHERE u.upload_id = ` + s.bind(1) + ` AND u.workspace_id = ` + s.bind(2) + ` AND u.repository_id = ` + s.bind(3) + ` AND u.token_id = ` + s.bind(4) + ` AND u.created_by = ` + s.bind(5) + ` AND u.reservation_id = ` + s.bind(6) + ` AND u.recovery_invalidated = 0 AND u.expires_at_ms > ` + s.bind(7) + ` AND r.recovery_invalidated = 0`
		var status string
		var verified int
		if err := tx.QueryRowContext(ctx, query, uploadID, workspace, repository, tokenID, actor, reservationID, time.Now().UTC().UnixMilli()).Scan(&status, &verified); errors.Is(err, sql.ErrNoRows) {
			return ErrNativeUploadUnavailable
		} else if err != nil {
			return errors.New("Pub native receipt could not be checked")
		}
		received = status == "uploaded" && verified == 1
		return nil
	})
	return received, err
}
