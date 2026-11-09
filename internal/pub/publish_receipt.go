package pub

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// PublishReceipt atomically links a verified receipt to an immutable version.
// It does not expose an pub endpoint, move dist-tags, serve files or establish
// complete backup. Native success must not be reported before commit.
func (s *ReservationService) PublishReceipt(ctx context.Context, bearer, workspace, repository, reservationID string) (string, error) {
	return s.publishReceipt(ctx, bearer, workspace, repository, reservationID, "")
}

// PublishNativeUpload rechecks the session inside the publication transaction.
func (s *ReservationService) PublishNativeUpload(ctx context.Context, bearer, workspace, repository, uploadID string) (string, error) {
	reservationID, err := s.NativeUploadReservation(ctx, bearer, workspace, repository, uploadID)
	if err != nil {
		return "", err
	}
	return s.publishReceipt(ctx, bearer, workspace, repository, reservationID, uploadID)
}

func (s *ReservationService) publishReceipt(ctx context.Context, bearer, workspace, repository, reservationID, uploadID string) (string, error) {
	if s == nil || ctx == nil {
		return "", ErrReservationUnavailable
	}
	id, err := uuid.Parse(reservationID)
	if err != nil || id.String() != reservationID {
		return "", ErrReservationUnavailable
	}
	var publishedID string
	err = s.repositories.WithPubWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, _ := strings.Cut(strings.TrimPrefix(bearer, "prpw_"), ".")
		if uploadID != "" {
			query := `SELECT EXISTS (SELECT 1 FROM registry_pub_native_uploads WHERE upload_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND token_id = ` + s.bind(4) + ` AND created_by = ` + s.bind(5) + ` AND reservation_id = ` + s.bind(6) + ` AND recovery_invalidated = 0 AND expires_at_ms > ` + s.bind(7) + `)`
			var allowed bool
			if err := tx.QueryRowContext(ctx, query, uploadID, workspace, repository, tokenID, actor, reservationID, time.Now().UTC().UnixMilli()).Scan(&allowed); err != nil {
				return errors.New("Pub native upload could not be checked")
			}
			if !allowed {
				return ErrNativeUploadUnavailable
			}
		}
		query := `SELECT name, version, version_identity, tarball_sha256, tarball_size, manifest FROM registry_pub_reservations WHERE reservation_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND created_by = ` + s.bind(4) + ` AND token_id = ` + s.bind(5) + ` AND status = 'uploaded' AND object_verified = 1 AND recovery_invalidated = 0`
		var name, version, versionKey, digest, manifest string
		var size int64
		if err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository, actor, tokenID).Scan(&name, &version, &versionKey, &digest, &size, &manifest); errors.Is(err, sql.ErrNoRows) {
			return ErrReservationUnavailable
		} else if err != nil {
			return errors.New("pub publication receipt could not be read")
		}
		query = `SELECT pub_version_id FROM registry_pub_publications WHERE reservation_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3)
		err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository).Scan(&publishedID)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.New("pub publication history could not be read")
		}
		if err := s.RequireCurrentApproval(ctx, tx, workspace, repository, reservationID, actor); err != nil {
			return err
		}
		if err := s.checkQuota(ctx, tx, workspace, repository, 0); err != nil {
			return err
		}
		query = `SELECT package_id FROM registry_pub_packages WHERE workspace_id = ` + s.bind(1) + ` AND repository_id = ` + s.bind(2) + ` AND name = ` + s.bind(3)
		var packageID string
		err = tx.QueryRowContext(ctx, query, workspace, repository, name).Scan(&packageID)
		if errors.Is(err, sql.ErrNoRows) {
			packageUUID, err := uuid.NewV7()
			if err != nil {
				return errors.New("pub package identity could not be created")
			}
			packageID = packageUUID.String()
			query = `INSERT INTO registry_pub_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `)`
			if _, err := tx.ExecContext(ctx, query, packageID, workspace, repository, name, actor, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				return errors.New("pub package could not be created")
			}
		} else if err != nil {
			return errors.New("pub package identity could not be checked")
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_pub_versions WHERE package_id = ` + s.bind(1) + ` AND version_identity = ` + s.bind(2) + `)`
		var exists bool
		if err := tx.QueryRowContext(ctx, query, packageID, versionKey).Scan(&exists); err != nil {
			return errors.New("pub version identity could not be checked")
		}
		if exists {
			return ErrReservationConflict
		}
		versionUUID, err := uuid.NewV7()
		if err != nil {
			return errors.New("pub version identity could not be created")
		}
		publishedID = versionUUID.String()
		now := time.Now().UTC().Format(time.RFC3339Nano)
		query = `INSERT INTO registry_pub_versions (pub_version_id, workspace_id, repository_id, package_id, version, version_identity, manifest, tarball_sha256, tarball_size, created_by, created_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `, ` + s.bind(7) + `, ` + s.bind(8) + `, ` + s.bind(9) + `, ` + s.bind(10) + `, ` + s.bind(11) + `)`
		if _, err := tx.ExecContext(ctx, query, publishedID, workspace, repository, packageID, version, versionKey, manifest, digest, size, actor, now); err != nil {
			return errors.New("pub version could not be published")
		}
		query = `INSERT INTO registry_pub_publications (reservation_id, pub_version_id, workspace_id, repository_id) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, reservationID, publishedID, workspace, repository); err != nil {
			return errors.New("pub publication linkage could not be recorded")
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("pub publication audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'user', 'pub.publication.created', 'pub_version', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), actor, publishedID, now); err != nil {
			return errors.New("pub publication could not be audited")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return publishedID, nil
}
