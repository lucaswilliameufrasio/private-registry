package gomod

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

type uploadReceipt struct {
	module, version, digest, sourceTime, status string
	mod                                         []byte
	size                                        int64
	invalidated                                 int
	reviewHold                                  int
	publishedID                                 sql.NullString
}

// PublishReservation makes an uploaded receipt visible atomically with its
// audit and quota transfer. It fails closed when human review is required;
// reviewer authorization and external publication remain unimplemented.
func (s *Service) PublishReservation(ctx context.Context, actorID, workspaceID, repositoryID, reservationID string) error {
	if s == nil || ctx == nil || !canonicalID(actorID) || !canonicalID(workspaceID) || !canonicalID(repositoryID) || !canonicalID(reservationID) {
		return ErrReservationUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrReservationUnavailable
	}
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
	readReceipt := func(queryer interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	}) (uploadReceipt, error) {
		query := `SELECT module_path, version, mod_bytes, zip_sha256, zip_size, source_time, status, recovery_invalidated, review_hold, published_version_id FROM registry_go_upload_sessions WHERE upload_session_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND created_by = ` + s.bind(4)
		var item uploadReceipt
		if err := queryer.QueryRowContext(ctx, query, reservationID, workspaceID, repositoryID, actorID).Scan(&item.module, &item.version, &item.mod, &item.digest, &item.size, &item.sourceTime, &item.status, &item.invalidated, &item.reviewHold, &item.publishedID); errors.Is(err, sql.ErrNoRows) {
			return uploadReceipt{}, ErrReservationUnavailable
		} else if err != nil {
			return uploadReceipt{}, errors.New("Go upload receipt could not be read")
		}
		return item, nil
	}
	receipt, err := readReceipt(s.db)
	if err != nil {
		return err
	}
	if receipt.invalidated != 0 || (receipt.status != "uploaded" && receipt.status != "published") || receipt.size < 1 || receipt.size > s.maxZip {
		return ErrReservationUnavailable
	}
	key, err := storage.NewObjectKey(workspaceID, receipt.digest)
	if err != nil || key.SHA256 != receipt.digest {
		return errors.New("Go upload receipt object is invalid")
	}
	reader, info, err := s.objects.Open(ctx, key)
	if err != nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		return errors.New("Go upload publication readback could not be opened")
	}
	hash := sha256.New()
	count, readErr := io.Copy(hash, &io.LimitedReader{R: &contextReader{ctx: ctx, source: reader}, N: receipt.size + 1})
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || count != receipt.size || info.Key != key || info.Size != receipt.size || hex.EncodeToString(hash.Sum(nil)) != receipt.digest {
		return errors.New("Go upload publication readback failed")
	}
	return s.repositories.WithRepositoryGrantTransaction(ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher, func(tx *sql.Tx) error {
		if err := repositories.RequireFormat(ctx, tx, s.driver, workspaceID, repositoryID, repositories.FormatGo); err != nil {
			return err
		}
		current, err := readReceipt(tx)
		if err != nil {
			return err
		}
		if current.invalidated != 0 || current.module != receipt.module || current.version != receipt.version || current.digest != receipt.digest || current.size != receipt.size || current.sourceTime != receipt.sourceTime || !bytes.Equal(current.mod, receipt.mod) {
			return ErrReservationUnavailable
		}
		if current.status == "published" && current.publishedID.Valid {
			query := `SELECT EXISTS (SELECT 1 FROM registry_go_module_versions WHERE module_version_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND module_path = ` + s.bind(4) + ` AND version = ` + s.bind(5) + ` AND zip_sha256 = ` + s.bind(6) + ` AND zip_size = ` + s.bind(7) + ` AND mod_bytes = ` + s.bind(8) + ` AND source_time = ` + s.bind(9) + `)`
			var exists bool
			if err := tx.QueryRowContext(ctx, query, current.publishedID.String, workspaceID, repositoryID, current.module, current.version, current.digest, current.size, current.mod, current.sourceTime).Scan(&exists); err != nil || !exists {
				return errors.New("published Go upload receipt is inconsistent")
			}
			return nil
		}
		if current.status != "uploaded" || current.publishedID.Valid {
			return ErrReservationUnavailable
		}
		if err := repositories.RequireGoPrivateNamespace(ctx, tx, s.driver, workspaceID, repositoryID, current.module); err != nil {
			return err
		}
		if err := s.requireValidReview(ctx, tx, workspaceID, repositoryID, reservationID, actorID, current.reviewHold); err != nil {
			return err
		}
		versionID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Go module version identity could not be generated")
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		query := `INSERT INTO registry_go_module_versions (module_version_id, workspace_id, repository_id, module_path, version, mod_bytes, zip_sha256, zip_size, source_time, created_by, created_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `, ` + s.bind(7) + `, ` + s.bind(8) + `, ` + s.bind(9) + `, ` + s.bind(10) + `, ` + s.bind(11) + `) ON CONFLICT (repository_id, module_path, version) DO NOTHING`
		result, err := tx.ExecContext(ctx, query, versionID.String(), workspaceID, repositoryID, current.module, current.version, current.mod, current.digest, current.size, current.sourceTime, actorID, now)
		if err != nil {
			return errors.New("Go module version could not be recorded")
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return ErrVersionExists
		}
		query = `UPDATE registry_go_upload_sessions SET status = 'published', published_version_id = ` + s.bind(1) + ` WHERE upload_session_id = ` + s.bind(2) + ` AND status = 'uploaded' AND recovery_invalidated = 0`
		result, err = tx.ExecContext(ctx, query, versionID.String(), reservationID)
		if err != nil {
			return errors.New("Go upload publication could not be recorded")
		}
		count, err = result.RowsAffected()
		if err != nil || count != 1 {
			return ErrReservationUnavailable
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Go publication audit identity could not be generated")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'go.module.published', 'go_module_version', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), actorID, versionID.String(), now); err != nil {
			return errors.New("Go module publication could not be audited")
		}
		return nil
	})
}
