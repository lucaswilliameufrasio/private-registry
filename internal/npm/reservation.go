package npm

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/repositories"
)

var (
	ErrReservationConflict    = errors.New("npm version is already reserved or published")
	ErrReservationQuota       = errors.New("npm logical quota is exceeded")
	ErrReservationUnavailable = errors.New("npm reservation is unavailable")
)

type ReservationRequest struct {
	Name           string
	Version        string
	TarballSHA256  string
	TarballSize    int64
	MetadataSHA256 string
}

type Reservation struct {
	ID        string
	ExpiresAt time.Time
}

type ReservationService struct {
	db           *sql.DB
	repositories *repositories.Service
	driver       config.DatabaseDriver
}

func NewReservationService(db *sql.DB, repos *repositories.Service, driver config.DatabaseDriver) (*ReservationService, error) {
	if db == nil || repos == nil || (driver != config.SQLite && driver != config.Postgres) {
		return nil, errors.New("npm reservation service parameters are invalid")
	}
	return &ReservationService{db: db, repositories: repos, driver: driver}, nil
}

func (s *ReservationService) bind(n int) string {
	if s.driver == config.Postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// Reserve commits only a bounded identity and quota reservation. The caller
// must authenticate before receiving a body and independently validate staged
// content; this method does not receive, review, publish or serve an object.
func (s *ReservationService) Reserve(ctx context.Context, bearer, workspace, repository string, request ReservationRequest) (Reservation, error) {
	if s == nil || ctx == nil || request.TarballSize < 1 || request.TarballSize > 64<<20 || !validDigest(request.TarballSHA256) || !validDigest(request.MetadataSHA256) {
		return Reservation{}, errors.New("npm reservation parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return Reservation{}, errors.New("npm reservation requires a deadline")
	}
	if err := ValidatePackageName(request.Name); err != nil {
		return Reservation{}, err
	}
	identity, err := VersionIdentity(request.Version)
	if err != nil {
		return Reservation{}, err
	}
	var result Reservation
	err = s.repositories.WithNPMWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, found := strings.Cut(strings.TrimPrefix(bearer, "prnw_"), ".")
		if !found {
			return repositories.ErrNPMWriteTokenUnavailable
		}
		now := time.Now().UTC().Truncate(time.Millisecond)
		query := `UPDATE registry_npm_reservations SET status = 'expired', upload_claim_id = NULL WHERE repository_id = ` + s.bind(1) + ` AND name = ` + s.bind(2) + ` AND status IN ('reserved', 'uploading') AND expires_at_ms <= ` + s.bind(3)
		if _, err := tx.ExecContext(ctx, query, repository, request.Name, now.UnixMilli()); err != nil {
			return errors.New("expired npm reservation could not be reconciled")
		}
		query = `SELECT reservation_id, version, tarball_sha256, tarball_size, metadata_sha256, token_id, created_by, expires_at_ms, recovery_invalidated, status FROM registry_npm_reservations WHERE repository_id = ` + s.bind(1) + ` AND name = ` + s.bind(2) + ` AND version_identity = ` + s.bind(3) + ` AND status IN ('reserved', 'uploading', 'uploaded')`
		var id, version, digest, metadata, storedToken, storedActor, status string
		var size, expires int64
		var invalidated int
		err := tx.QueryRowContext(ctx, query, repository, request.Name, identity).Scan(&id, &version, &digest, &size, &metadata, &storedToken, &storedActor, &expires, &invalidated, &status)
		if err == nil {
			if version != request.Version || digest != request.TarballSHA256 || size != request.TarballSize || metadata != request.MetadataSHA256 || storedToken != tokenID || storedActor != actor || invalidated != 0 || (status != "uploaded" && expires <= now.UnixMilli()) {
				return ErrReservationConflict
			}
			result = Reservation{ID: id, ExpiresAt: time.UnixMilli(expires).UTC()}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.New("npm reservation identity could not be checked")
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_npm_versions v JOIN registry_npm_packages p ON p.package_id = v.package_id WHERE p.repository_id = ` + s.bind(1) + ` AND p.name = ` + s.bind(2) + ` AND v.version_identity = ` + s.bind(3) + `)`
		var exists bool
		if err := tx.QueryRowContext(ctx, query, repository, request.Name, identity).Scan(&exists); err != nil {
			return errors.New("npm published identity could not be checked")
		}
		if exists {
			return ErrReservationConflict
		}
		if err := s.checkQuota(ctx, tx, workspace, repository, request.TarballSize); err != nil {
			return err
		}
		idValue, err := uuid.NewV7()
		if err != nil {
			return errors.New("npm reservation identity could not be created")
		}
		result = Reservation{ID: idValue.String(), ExpiresAt: now.Add(30 * time.Minute)}
		query = `INSERT INTO registry_npm_reservations (reservation_id, workspace_id, repository_id, name, version, version_identity, tarball_sha256, tarball_size, metadata_sha256, token_id, created_by, status, created_at_ms, expires_at_ms) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `, ` + s.bind(7) + `, ` + s.bind(8) + `, ` + s.bind(9) + `, ` + s.bind(10) + `, ` + s.bind(11) + `, 'reserved', ` + s.bind(12) + `, ` + s.bind(13) + `)`
		if _, err := tx.ExecContext(ctx, query, result.ID, workspace, repository, request.Name, request.Version, identity, request.TarballSHA256, request.TarballSize, request.MetadataSHA256, tokenID, actor, now.UnixMilli(), result.ExpiresAt.UnixMilli()); err != nil {
			return errors.New("npm reservation could not be created")
		}
		return s.audit(ctx, tx, actor, "npm.reservation.created", result.ID, now)
	})
	if err != nil {
		return Reservation{}, err
	}
	return result, nil
}

func (s *ReservationService) audit(ctx context.Context, tx *sql.Tx, actor, action, id string, now time.Time) error {
	auditID, err := uuid.NewV7()
	if err != nil {
		return errors.New("npm reservation audit identity could not be created")
	}
	query := `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'user', ` + s.bind(3) + `, 'npm_reservation', ` + s.bind(4) + `, 'succeeded', ` + s.bind(5) + `)`
	if _, err := tx.ExecContext(ctx, query, auditID.String(), actor, action, id, now.Format(time.RFC3339Nano)); err != nil {
		return errors.New("npm reservation could not be audited")
	}
	return nil
}

// checkQuota is called while the repository grant coordination lock is held.
// Subtract each source separately to avoid overflowing a combined sum.
func (s *ReservationService) checkQuota(ctx context.Context, tx *sql.Tx, workspace, repository string, size int64) error {
	query := `SELECT w.logical_quota_bytes, r.logical_quota_bytes FROM registry_workspaces w JOIN registry_repositories r ON r.workspace_id = w.workspace_id WHERE w.workspace_id = ` + s.bind(1) + ` AND r.repository_id = ` + s.bind(2)
	var workspaceLimit, repositoryLimit sql.NullInt64
	if err := tx.QueryRowContext(ctx, query, workspace, repository).Scan(&workspaceLimit, &repositoryLimit); err != nil {
		return errors.New("npm quota policy could not be read")
	}
	for _, limit := range []struct {
		value      sql.NullInt64
		repository bool
	}{{workspaceLimit, false}, {repositoryLimit, true}} {
		if !limit.value.Valid {
			continue
		}
		if size > limit.value.Int64 {
			return ErrReservationQuota
		}
		remaining := limit.value.Int64 - size
		for _, source := range []struct{ table, expression, condition string }{
			{"registry_generic_upload_sessions", "expected_size", " AND status IN ('receiving', 'uploading', 'uploaded', 'published')"},
			{"registry_go_module_versions", "zip_size + LENGTH(mod_bytes)", ""},
			{"registry_go_upload_sessions", "zip_size + LENGTH(mod_bytes)", " AND status IN ('receiving', 'uploading', 'uploaded')"},
			{"registry_cargo_versions", "archive_size", ""},
			{"registry_cargo_reservations", "archive_size", " AND status IN ('reserved', 'uploading', 'uploaded') AND NOT EXISTS (SELECT 1 FROM registry_cargo_publications p WHERE p.reservation_id = registry_cargo_reservations.reservation_id)"},
			{"registry_npm_versions", "tarball_size", ""},
			{"registry_npm_reservations", "tarball_size", " AND status IN ('reserved', 'uploading', 'uploaded') AND NOT EXISTS (SELECT 1 FROM registry_npm_publications p WHERE p.reservation_id = registry_npm_reservations.reservation_id)"},
		} {
			if limit.repository && source.table != "registry_npm_versions" && source.table != "registry_npm_reservations" {
				continue
			}
			query := `SELECT COALESCE(SUM(` + source.expression + `), 0) FROM ` + source.table + ` WHERE workspace_id = ` + s.bind(1) + source.condition
			args := []any{workspace}
			if limit.repository {
				query += ` AND repository_id = ` + s.bind(2)
				args = append(args, repository)
			}
			var used int64
			if err := tx.QueryRowContext(ctx, query, args...).Scan(&used); err != nil || used < 0 {
				return errors.New("npm quota usage could not be read")
			}
			if used > remaining {
				return ErrReservationQuota
			}
			remaining -= used
		}
	}
	return nil
}

// Cancel releases an unexpired reservation belonging to the exact credential.
// It never deletes content, cancels a published version or approves review.
func (s *ReservationService) Cancel(ctx context.Context, bearer, workspace, repository, reservationID string) error {
	if s == nil || ctx == nil {
		return ErrReservationUnavailable
	}
	id, err := uuid.Parse(reservationID)
	if err != nil || id.String() != reservationID {
		return ErrReservationUnavailable
	}
	return s.repositories.WithNPMWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, found := strings.Cut(strings.TrimPrefix(bearer, "prnw_"), ".")
		if !found {
			return repositories.ErrNPMWriteTokenUnavailable
		}
		query := `SELECT status, recovery_invalidated, expires_at_ms FROM registry_npm_reservations WHERE reservation_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND token_id = ` + s.bind(4) + ` AND created_by = ` + s.bind(5)
		var status string
		var invalidated int
		var expires int64
		if err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository, tokenID, actor).Scan(&status, &invalidated, &expires); errors.Is(err, sql.ErrNoRows) {
			return ErrReservationUnavailable
		} else if err != nil {
			return errors.New("npm reservation cancellation could not be checked")
		}
		if invalidated != 0 {
			return ErrReservationUnavailable
		}
		if status == "cancelled" {
			return nil
		}
		now := time.Now().UTC()
		if status != "reserved" || expires <= now.UnixMilli() {
			return ErrReservationUnavailable
		}
		query = `UPDATE registry_npm_reservations SET status = 'cancelled' WHERE reservation_id = ` + s.bind(1) + ` AND status = 'reserved' AND recovery_invalidated = 0`
		changed, err := tx.ExecContext(ctx, query, reservationID)
		if err != nil {
			return errors.New("npm reservation could not be cancelled")
		}
		count, err := changed.RowsAffected()
		if err != nil || count != 1 {
			return ErrReservationUnavailable
		}
		return s.audit(ctx, tx, actor, "npm.reservation.cancelled", reservationID, now)
	})
}
