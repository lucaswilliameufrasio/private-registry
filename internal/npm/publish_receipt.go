package npm

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// PublishReceipt atomically links a verified receipt to an immutable version.
// It does not expose an npm endpoint, move dist-tags, serve files or establish
// complete backup. Native success must not be reported before commit.
func (s *ReservationService) PublishReceipt(ctx context.Context, bearer, workspace, repository, reservationID string) (string, error) {
	if s == nil || ctx == nil {
		return "", ErrReservationUnavailable
	}
	id, err := uuid.Parse(reservationID)
	if err != nil || id.String() != reservationID {
		return "", ErrReservationUnavailable
	}
	var publishedID string
	err = s.repositories.WithNPMWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, _ := strings.Cut(strings.TrimPrefix(bearer, "prnw_"), ".")
		query := `SELECT name, version, version_identity, tarball_sha256, tarball_size, manifest, integrity FROM registry_npm_reservations WHERE reservation_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND created_by = ` + s.bind(4) + ` AND token_id = ` + s.bind(5) + ` AND status = 'uploaded' AND object_verified = 1 AND recovery_invalidated = 0`
		var name, version, versionKey, digest, manifest, integrity string
		var size int64
		if err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository, actor, tokenID).Scan(&name, &version, &versionKey, &digest, &size, &manifest, &integrity); errors.Is(err, sql.ErrNoRows) {
			return ErrReservationUnavailable
		} else if err != nil {
			return errors.New("npm publication receipt could not be read")
		}
		query = `SELECT npm_version_id FROM registry_npm_publications WHERE reservation_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3)
		err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository).Scan(&publishedID)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.New("npm publication history could not be read")
		}
		if err := s.RequireCurrentApproval(ctx, tx, workspace, repository, reservationID, actor); err != nil {
			return err
		}
		if err := s.checkQuota(ctx, tx, workspace, repository, 0); err != nil {
			return err
		}
		query = `SELECT package_id FROM registry_npm_packages WHERE workspace_id = ` + s.bind(1) + ` AND repository_id = ` + s.bind(2) + ` AND name = ` + s.bind(3)
		var packageID string
		err = tx.QueryRowContext(ctx, query, workspace, repository, name).Scan(&packageID)
		if errors.Is(err, sql.ErrNoRows) {
			packageUUID, err := uuid.NewV7()
			if err != nil {
				return errors.New("npm package identity could not be created")
			}
			packageID = packageUUID.String()
			query = `INSERT INTO registry_npm_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `)`
			if _, err := tx.ExecContext(ctx, query, packageID, workspace, repository, name, actor, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				return errors.New("npm package could not be created")
			}
		} else if err != nil {
			return errors.New("npm package identity could not be checked")
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_npm_versions WHERE package_id = ` + s.bind(1) + ` AND version_identity = ` + s.bind(2) + `)`
		var exists bool
		if err := tx.QueryRowContext(ctx, query, packageID, versionKey).Scan(&exists); err != nil {
			return errors.New("npm version identity could not be checked")
		}
		if exists {
			return ErrReservationConflict
		}
		versionUUID, err := uuid.NewV7()
		if err != nil {
			return errors.New("npm version identity could not be created")
		}
		publishedID = versionUUID.String()
		now := time.Now().UTC().Format(time.RFC3339Nano)
		query = `INSERT INTO registry_npm_versions (npm_version_id, workspace_id, repository_id, package_id, version, version_identity, manifest, tarball_sha256, tarball_size, integrity, created_by, created_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `, ` + s.bind(7) + `, ` + s.bind(8) + `, ` + s.bind(9) + `, ` + s.bind(10) + `, ` + s.bind(11) + `, ` + s.bind(12) + `)`
		if _, err := tx.ExecContext(ctx, query, publishedID, workspace, repository, packageID, version, versionKey, manifest, digest, size, integrity, actor, now); err != nil {
			return errors.New("npm version could not be published")
		}
		query = `INSERT INTO registry_npm_publications (reservation_id, npm_version_id, workspace_id, repository_id) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, reservationID, publishedID, workspace, repository); err != nil {
			return errors.New("npm publication linkage could not be recorded")
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("npm publication audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'user', 'npm.publication.created', 'npm_version', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), actor, publishedID, now); err != nil {
			return errors.New("npm publication could not be audited")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return publishedID, nil
}
