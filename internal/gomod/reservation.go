package gomod

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/mod/modfile"
	modulezip "golang.org/x/mod/zip"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

var (
	ErrReservationConflict = errors.New("Go module version is already reserved")
	ErrQuotaExceeded       = errors.New("Go module logical storage quota is exceeded")
)

type ReservationRequest struct {
	ModulePath string
	Version    string
	SourceTime time.Time
	ModBytes   []byte
	ZipSize    int64
	ZipSHA256  string
}

type Reservation struct {
	ID        string
	ExpiresAt time.Time
}

type ReservationStatus struct {
	ID          string
	ModulePath  string
	Version     string
	Status      string
	ExpiresAt   time.Time
	ReviewHeld  bool
	ReviewState string
	Invalidated bool
}

// GetReservation lets the original publisher reconcile an uncertain response.
// It rechecks the current grant and never returns another publisher's session.
func (s *Service) GetReservation(ctx context.Context, actorID, workspaceID, repositoryID, reservationID string) (ReservationStatus, error) {
	if s == nil || ctx == nil || !canonicalID(actorID) || !canonicalID(workspaceID) || !canonicalID(repositoryID) || !canonicalID(reservationID) {
		return ReservationStatus{}, ErrReservationUnavailable
	}
	var item ReservationStatus
	err := s.repositories.WithRepositoryGrantTransaction(ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher, func(tx *sql.Tx) error {
		if err := repositories.RequireFormat(ctx, tx, s.driver, workspaceID, repositoryID, repositories.FormatGo); err != nil {
			return err
		}
		query := `SELECT upload_session_id, module_path, version, status, expires_at_ms, review_hold, recovery_invalidated FROM registry_go_upload_sessions WHERE upload_session_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND created_by = ` + s.bind(4)
		var expires int64
		var hold, invalidated int
		if err := tx.QueryRowContext(ctx, query, reservationID, workspaceID, repositoryID, actorID).Scan(&item.ID, &item.ModulePath, &item.Version, &item.Status, &expires, &hold, &invalidated); errors.Is(err, sql.ErrNoRows) {
			return ErrReservationUnavailable
		} else if err != nil {
			return errors.New("Go upload reservation could not be read")
		}
		item.ExpiresAt = time.UnixMilli(expires).UTC()
		item.ReviewHeld = hold == 1
		item.Invalidated = invalidated == 1
		item.ReviewState = "not_required"
		if item.Invalidated {
			item.ReviewState = "recovery_required"
		} else if item.ReviewHeld {
			switch item.Status {
			case "receiving", "uploading":
				item.ReviewState = "awaiting_upload"
			case "uploaded":
				item.ReviewState = "awaiting_review"
				if err := s.requireValidReview(ctx, tx, workspaceID, repositoryID, reservationID, actorID, hold); err == nil {
					item.ReviewState = "approved"
				} else if !errors.Is(err, repositories.ErrReviewRequired) {
					return err
				}
			case "published":
				item.ReviewState = "completed"
			default:
				item.ReviewState = "closed"
			}
		}
		return nil
	})
	if err != nil {
		return ReservationStatus{}, err
	}
	return item, nil
}

// ReservePublication persists a version identity and logical bytes before
// receiving content. Publication and review are distinct later operations.
func (s *Service) ReservePublication(ctx context.Context, actorID, workspaceID, repositoryID string, request ReservationRequest) (Reservation, error) {
	if s == nil || ctx == nil || !canonicalID(actorID) || !canonicalID(workspaceID) || !canonicalID(repositoryID) || len(request.ModulePath) > 1024 || len(request.Version) > 200 || len(request.ModBytes) < 1 || len(request.ModBytes) > modulezip.MaxGoMod || request.ZipSize < 1 || request.ZipSize > s.maxZip {
		return Reservation{}, ErrInvalidPublication
	}
	if _, ok := ctx.Deadline(); !ok {
		return Reservation{}, ErrInvalidPublication
	}
	info, err := NewVersionInfo(request.ModulePath, request.Version, request.SourceTime)
	if err != nil {
		return Reservation{}, ErrInvalidPublication
	}
	mod := bytes.Clone(request.ModBytes)
	parsed, err := modfile.Parse("go.mod", mod, nil)
	if err != nil || parsed.Module == nil || parsed.Module.Mod.Path != request.ModulePath {
		return Reservation{}, ErrInvalidPublication
	}
	key, err := storage.NewObjectKey(workspaceID, request.ZipSHA256)
	if err != nil || key.SHA256 != request.ZipSHA256 {
		return Reservation{}, ErrInvalidPublication
	}
	var reservation Reservation
	err = s.repositories.WithRepositoryGrantTransaction(ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher, func(tx *sql.Tx) error {
		if err := repositories.RequireFormat(ctx, tx, s.driver, workspaceID, repositoryID, repositories.FormatGo); err != nil {
			return err
		}
		if err := repositories.RequireGoPrivateNamespace(ctx, tx, s.driver, workspaceID, repositoryID, request.ModulePath); err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Millisecond)
		query := `UPDATE registry_go_upload_sessions SET status = 'expired', upload_claim_id = NULL WHERE repository_id = ` + s.bind(1) + ` AND module_path = ` + s.bind(2) + ` AND version = ` + s.bind(3) + ` AND status IN ('receiving', 'uploading') AND expires_at_ms <= ` + s.bind(4)
		if _, err := tx.ExecContext(ctx, query, repositoryID, request.ModulePath, request.Version, now.UnixMilli()); err != nil {
			return errors.New("expired Go upload reservation could not be reconciled")
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_go_module_versions WHERE repository_id = ` + s.bind(1) + ` AND module_path = ` + s.bind(2) + ` AND version = ` + s.bind(3) + `)`
		var exists bool
		if err := tx.QueryRowContext(ctx, query, repositoryID, request.ModulePath, request.Version).Scan(&exists); err != nil {
			return errors.New("Go module version could not be checked")
		}
		if exists {
			return ErrVersionExists
		}
		query = `SELECT upload_session_id, created_by, mod_bytes, zip_sha256, zip_size, source_time, expires_at_ms, recovery_invalidated FROM registry_go_upload_sessions WHERE repository_id = ` + s.bind(1) + ` AND module_path = ` + s.bind(2) + ` AND version = ` + s.bind(3) + ` AND status IN ('receiving', 'uploading', 'uploaded')`
		var existingID, existingActor, existingDigest, existingTime string
		var existingMod []byte
		var existingSize, existingExpiry int64
		var invalidated int
		err = tx.QueryRowContext(ctx, query, repositoryID, request.ModulePath, request.Version).Scan(&existingID, &existingActor, &existingMod, &existingDigest, &existingSize, &existingTime, &existingExpiry, &invalidated)
		if err == nil {
			if invalidated == 0 && existingActor == actorID && existingDigest == key.SHA256 && existingSize == request.ZipSize && existingTime == info.Time.Format(time.RFC3339Nano) && bytes.Equal(existingMod, mod) {
				reservation = Reservation{ID: existingID, ExpiresAt: time.UnixMilli(existingExpiry).UTC()}
				return nil
			}
			return ErrReservationConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.New("Go upload reservation could not be checked")
		}
		if err := s.checkReservationQuota(ctx, tx, workspaceID, repositoryID, request.ZipSize+int64(len(mod))); err != nil {
			return err
		}
		var reviewHold int
		query = `SELECT review_required FROM registry_repositories WHERE workspace_id = ` + s.bind(1) + ` AND repository_id = ` + s.bind(2)
		if err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&reviewHold); err != nil {
			return errors.New("Go upload review policy could not be read")
		}
		id, err := uuid.NewV7()
		if err != nil {
			return errors.New("Go upload reservation identity could not be created")
		}
		expires := now.Add(24 * time.Hour)
		query = `INSERT INTO registry_go_upload_sessions (upload_session_id, workspace_id, repository_id, module_path, version, mod_bytes, zip_sha256, zip_size, source_time, status, created_by, created_at_ms, expires_at_ms, review_hold) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `, ` + s.bind(7) + `, ` + s.bind(8) + `, ` + s.bind(9) + `, 'receiving', ` + s.bind(10) + `, ` + s.bind(11) + `, ` + s.bind(12) + `, ` + s.bind(13) + `)`
		if _, err := tx.ExecContext(ctx, query, id.String(), workspaceID, repositoryID, request.ModulePath, request.Version, mod, key.SHA256, request.ZipSize, info.Time.Format(time.RFC3339Nano), actorID, now.UnixMilli(), expires.UnixMilli(), reviewHold); err != nil {
			return errors.New("Go upload reservation could not be created")
		}
		reservation = Reservation{ID: id.String(), ExpiresAt: expires}
		return nil
	})
	if err != nil {
		return Reservation{}, err
	}
	return reservation, nil
}

func (s *Service) checkReservationQuota(ctx context.Context, tx *sql.Tx, workspaceID, repositoryID string, size int64) error {
	query := `SELECT w.logical_quota_bytes, r.logical_quota_bytes FROM registry_workspaces w JOIN registry_repositories r ON r.workspace_id = w.workspace_id WHERE w.workspace_id = ` + s.bind(1) + ` AND r.repository_id = ` + s.bind(2)
	var workspaceLimit, repositoryLimit sql.NullInt64
	if err := tx.QueryRowContext(ctx, query, workspaceID, repositoryID).Scan(&workspaceLimit, &repositoryLimit); err != nil {
		return errors.New("Go upload quota policy could not be read")
	}
	for _, limit := range []struct {
		value      sql.NullInt64
		repository bool
	}{{workspaceLimit, false}, {repositoryLimit, true}} {
		if !limit.value.Valid {
			continue
		}
		remaining := limit.value.Int64
		if size > remaining {
			return ErrQuotaExceeded
		}
		remaining -= size
		for _, table := range []string{"registry_generic_upload_sessions", "registry_go_module_versions", "registry_go_upload_sessions", "registry_cargo_versions", "registry_cargo_reservations", "registry_npm_versions", "registry_npm_reservations", "registry_pub_versions", "registry_pub_reservations"} {
			if limit.repository && (table == "registry_generic_upload_sessions" || table == "registry_cargo_versions" || table == "registry_cargo_reservations" || table == "registry_npm_versions" || table == "registry_npm_reservations" || table == "registry_pub_versions" || table == "registry_pub_reservations") {
				continue
			}
			expression, condition := "zip_size + LENGTH(mod_bytes)", ""
			if table == "registry_generic_upload_sessions" {
				expression, condition = "expected_size", " AND status IN ('receiving', 'uploading', 'uploaded', 'published')"
			} else if table == "registry_go_upload_sessions" {
				condition = " AND status IN ('receiving', 'uploading', 'uploaded')"
			} else if table == "registry_cargo_versions" {
				expression = "archive_size"
			} else if table == "registry_cargo_reservations" {
				expression, condition = "archive_size", " AND status IN ('reserved', 'uploading', 'uploaded') AND NOT EXISTS (SELECT 1 FROM registry_cargo_publications p WHERE p.reservation_id = registry_cargo_reservations.reservation_id)"
			} else if table == "registry_npm_versions" {
				expression = "tarball_size"
			} else if table == "registry_pub_versions" {
				expression = "tarball_size"
			} else if table == "registry_pub_reservations" {
				expression, condition = "tarball_size", " AND status IN ('reserved', 'uploading', 'uploaded')"
			} else if table == "registry_npm_reservations" {
				expression, condition = "tarball_size", " AND status IN ('reserved', 'uploading', 'uploaded') AND NOT EXISTS (SELECT 1 FROM registry_npm_publications p WHERE p.reservation_id = registry_npm_reservations.reservation_id)"
			}
			query := `SELECT COALESCE(SUM(` + expression + `), 0) FROM ` + table + ` WHERE workspace_id = ` + s.bind(1) + condition
			args := []any{workspaceID}
			if limit.repository {
				query += ` AND repository_id = ` + s.bind(2)
				args = append(args, repositoryID)
			}
			var used int64
			if err := tx.QueryRowContext(ctx, query, args...).Scan(&used); err != nil || used < 0 {
				return errors.New("Go upload quota usage could not be read")
			}
			if used > remaining {
				return ErrQuotaExceeded
			}
			remaining -= used
		}
	}
	return nil
}

// CancelReservation releases an unpublished reservation owned by the current
// publisher. Verified objects remain referenced for future backup and GC;
// cancellation does not imply physical deletion or approve a review.
func (s *Service) CancelReservation(ctx context.Context, actorID, workspaceID, repositoryID, reservationID string) error {
	if s == nil || ctx == nil || !canonicalID(actorID) || !canonicalID(workspaceID) || !canonicalID(repositoryID) || !canonicalID(reservationID) {
		return ErrReservationUnavailable
	}
	return s.repositories.WithRepositoryGrantTransaction(ctx, actorID, workspaceID, repositoryID, repositories.GrantPublisher, func(tx *sql.Tx) error {
		query := `SELECT status, recovery_invalidated FROM registry_go_upload_sessions WHERE upload_session_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND created_by = ` + s.bind(4)
		var status string
		var invalidated int
		if err := tx.QueryRowContext(ctx, query, reservationID, workspaceID, repositoryID, actorID).Scan(&status, &invalidated); errors.Is(err, sql.ErrNoRows) {
			return ErrReservationUnavailable
		} else if err != nil {
			return errors.New("Go upload cancellation state could not be read")
		}
		if invalidated != 0 {
			return ErrReservationUnavailable
		}
		if status == "rejected" {
			return nil
		}
		if status != "receiving" && status != "uploaded" {
			return ErrReservationUnavailable
		}
		query = `UPDATE registry_go_upload_sessions SET status = 'rejected' WHERE upload_session_id = ` + s.bind(1) + ` AND status = ` + s.bind(2) + ` AND recovery_invalidated = 0`
		result, err := tx.ExecContext(ctx, query, reservationID, status)
		if err != nil {
			return errors.New("Go upload cancellation could not be recorded")
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return ErrReservationUnavailable
		}
		id, err := uuid.NewV7()
		if err != nil {
			return errors.New("Go upload cancellation audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'go.upload.cancelled', 'go_upload', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, id.String(), actorID, reservationID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return errors.New("Go upload cancellation could not be audited")
		}
		return nil
	})
}
