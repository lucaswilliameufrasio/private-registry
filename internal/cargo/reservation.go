package cargo

import (
	"context"
	"crypto/sha256"
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
	ErrReservationConflict    = errors.New("Cargo version is already reserved or published")
	ErrReservationQuota       = errors.New("Cargo logical quota is exceeded")
	ErrReservationUnavailable = errors.New("Cargo reservation is unavailable")
)

type ReservationService struct {
	db           *sql.DB
	repositories *repositories.Service
	driver       config.DatabaseDriver
}

// Cancel releases an unexpired reservation owned by the exact credential. It
// does not delete objects, approve a review, or cancel a published version.
func (s *ReservationService) Cancel(ctx context.Context, bearer, workspace, repository, reservationID string) error {
	if s == nil || ctx == nil {
		return ErrReservationUnavailable
	}
	id, err := uuid.Parse(reservationID)
	if err != nil || id.String() != reservationID {
		return ErrReservationUnavailable
	}
	return s.repositories.WithCargoWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, found := strings.Cut(strings.TrimPrefix(bearer, "prcw_"), ".")
		if !found {
			return repositories.ErrCargoWriteTokenUnavailable
		}
		query := `SELECT status, recovery_invalidated, expires_at_ms FROM registry_cargo_reservations WHERE reservation_id = ` + s.bind(1) + ` AND workspace_id = ` + s.bind(2) + ` AND repository_id = ` + s.bind(3) + ` AND token_id = ` + s.bind(4) + ` AND created_by = ` + s.bind(5)
		var status string
		var invalidated int
		var expires int64
		if err := tx.QueryRowContext(ctx, query, reservationID, workspace, repository, tokenID, actor).Scan(&status, &invalidated, &expires); errors.Is(err, sql.ErrNoRows) {
			return ErrReservationUnavailable
		} else if err != nil {
			return errors.New("Cargo reservation cancellation could not be checked")
		}
		if invalidated != 0 {
			return ErrReservationUnavailable
		}
		if status == "cancelled" {
			return nil
		}
		if status != "reserved" || expires <= time.Now().UTC().UnixMilli() {
			return ErrReservationUnavailable
		}
		query = `UPDATE registry_cargo_reservations SET status = 'cancelled' WHERE reservation_id = ` + s.bind(1) + ` AND status = 'reserved' AND recovery_invalidated = 0`
		result, err := tx.ExecContext(ctx, query, reservationID)
		if err != nil {
			return errors.New("Cargo reservation could not be cancelled")
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return ErrReservationUnavailable
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Cargo cancellation audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'user', 'cargo.reservation.cancelled', 'cargo_reservation', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), actor, reservationID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return errors.New("Cargo reservation cancellation could not be audited")
		}
		return nil
	})
}

type Reservation struct {
	ID        string
	ExpiresAt time.Time
}

func NewReservationService(db *sql.DB, repos *repositories.Service, driver config.DatabaseDriver) (*ReservationService, error) {
	if db == nil || repos == nil || (driver != config.SQLite && driver != config.Postgres) {
		return nil, errors.New("Cargo reservation service parameters are invalid")
	}
	return &ReservationService{db: db, repositories: repos, driver: driver}, nil
}

// Reserve creates a durable identity and quota reservation, not a publication.
// The caller must authenticate before reading the body, bound aggregate staging
// and discard staging on failure. Metadata and archive still require complete
// validation, review and reauthorization before storage or serving.
func (s *ReservationService) Reserve(ctx context.Context, bearer, workspace, repository string, frame PublishFrame) (Reservation, error) {
	if s == nil || ctx == nil || frame.Size < 1 || frame.Size > 500<<20 {
		return Reservation{}, errors.New("Cargo reservation parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return Reservation{}, errors.New("Cargo reservation requires a deadline")
	}
	entry, err := ProjectIndex(frame.Metadata, frame.SHA256)
	if err != nil {
		return Reservation{}, err
	}
	nameKey, err := NameIdentity(entry.Name)
	if err != nil {
		return Reservation{}, err
	}
	versionKey, err := VersionIdentity(entry.Version)
	if err != nil {
		return Reservation{}, err
	}
	metadataDigest := sha256.Sum256(frame.Metadata)
	metadataHash := hex.EncodeToString(metadataDigest[:])
	var result Reservation
	err = s.repositories.WithCargoWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		tokenID, _, found := strings.Cut(strings.TrimPrefix(bearer, "prcw_"), ".")
		if !found {
			return repositories.ErrCargoWriteTokenUnavailable
		}
		now := time.Now().UTC().Truncate(time.Millisecond)
		query := `UPDATE registry_cargo_reservations SET status = 'expired', upload_claim_id = NULL WHERE repository_id = ` + s.bind(1) + ` AND name_identity = ` + s.bind(2) + ` AND status IN ('reserved', 'uploading') AND expires_at_ms <= ` + s.bind(3)
		if _, err := tx.ExecContext(ctx, query, repository, nameKey, now.UnixMilli()); err != nil {
			return errors.New("expired Cargo reservation could not be reconciled")
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_cargo_packages WHERE repository_id = ` + s.bind(1) + ` AND name_identity = ` + s.bind(2) + ` AND name <> ` + s.bind(3) + `)`
		var exists bool
		if err := tx.QueryRowContext(ctx, query, repository, nameKey, entry.Name).Scan(&exists); err != nil {
			return errors.New("Cargo package identity could not be checked")
		}
		if exists {
			return ErrReservationConflict
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_cargo_reservations WHERE repository_id = ` + s.bind(1) + ` AND name_identity = ` + s.bind(2) + ` AND name <> ` + s.bind(3) + ` AND status IN ('reserved', 'uploading', 'uploaded'))`
		if err := tx.QueryRowContext(ctx, query, repository, nameKey, entry.Name).Scan(&exists); err != nil {
			return errors.New("Cargo reserved package identity could not be checked")
		}
		if exists {
			return ErrReservationConflict
		}
		query = `SELECT reservation_id, name, version, archive_sha256, archive_size, metadata_sha256, token_id, created_by, expires_at_ms, recovery_invalidated FROM registry_cargo_reservations WHERE repository_id = ` + s.bind(1) + ` AND name_identity = ` + s.bind(2) + ` AND version_identity = ` + s.bind(3) + ` AND status IN ('reserved', 'uploading', 'uploaded')`
		var existingID, name, version, digest, metadata, existingToken, existingActor string
		var size, expires int64
		var invalidated int
		err := tx.QueryRowContext(ctx, query, repository, nameKey, versionKey).Scan(&existingID, &name, &version, &digest, &size, &metadata, &existingToken, &existingActor, &expires, &invalidated)
		if err == nil {
			if invalidated == 0 && name == entry.Name && version == entry.Version && digest == frame.SHA256 && size == frame.Size && metadata == metadataHash && existingToken == tokenID && existingActor == actor {
				result = Reservation{ID: existingID, ExpiresAt: time.UnixMilli(expires).UTC()}
				return nil
			}
			return ErrReservationConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.New("Cargo reservation could not be checked")
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_cargo_packages p JOIN registry_cargo_versions v ON v.package_id = p.package_id WHERE p.repository_id = ` + s.bind(1) + ` AND p.name_identity = ` + s.bind(2) + ` AND v.version_identity = ` + s.bind(3) + `)`
		if err := tx.QueryRowContext(ctx, query, repository, nameKey, versionKey).Scan(&exists); err != nil {
			return errors.New("Cargo version identity could not be checked")
		}
		if exists {
			return ErrReservationConflict
		}
		if err := s.checkQuota(ctx, tx, workspace, repository, frame.Size); err != nil {
			return err
		}
		id, err := uuid.NewV7()
		if err != nil {
			return errors.New("Cargo reservation identity could not be created")
		}
		expiresAt := now.Add(24 * time.Hour)
		var reviewHold int
		query = `SELECT review_required FROM registry_repositories WHERE workspace_id = ` + s.bind(1) + ` AND repository_id = ` + s.bind(2)
		if err := tx.QueryRowContext(ctx, query, workspace, repository).Scan(&reviewHold); err != nil {
			return errors.New("Cargo review policy could not be read")
		}
		query = `INSERT INTO registry_cargo_reservations (reservation_id, workspace_id, repository_id, name, name_identity, version, version_identity, archive_sha256, archive_size, metadata_sha256, token_id, created_by, status, review_hold, created_at_ms, expires_at_ms) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, ` + s.bind(3) + `, ` + s.bind(4) + `, ` + s.bind(5) + `, ` + s.bind(6) + `, ` + s.bind(7) + `, ` + s.bind(8) + `, ` + s.bind(9) + `, ` + s.bind(10) + `, ` + s.bind(11) + `, ` + s.bind(12) + `, 'reserved', ` + s.bind(13) + `, ` + s.bind(14) + `, ` + s.bind(15) + `)`
		if _, err := tx.ExecContext(ctx, query, id.String(), workspace, repository, entry.Name, nameKey, entry.Version, versionKey, frame.SHA256, frame.Size, metadataHash, tokenID, actor, reviewHold, now.UnixMilli(), expiresAt.UnixMilli()); err != nil {
			return errors.New("Cargo reservation could not be created")
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Cargo reservation audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'user', 'cargo.reservation.created', 'cargo_reservation', ` + s.bind(3) + `, 'succeeded', ` + s.bind(4) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), actor, id.String(), now.Format(time.RFC3339Nano)); err != nil {
			return errors.New("Cargo reservation could not be audited")
		}
		result = Reservation{ID: id.String(), ExpiresAt: expiresAt}
		return nil
	})
	if err != nil {
		return Reservation{}, err
	}
	return result, nil
}

func (s *ReservationService) bind(n int) string {
	if s.driver == config.Postgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// checkQuota is called under the installation coordination lock. Cargo
// versions and active reservations are counted once by their archive bytes.
func (s *ReservationService) checkQuota(ctx context.Context, tx *sql.Tx, workspace, repository string, size int64) error {
	query := `SELECT w.logical_quota_bytes, r.logical_quota_bytes FROM registry_workspaces w JOIN registry_repositories r ON r.workspace_id = w.workspace_id WHERE w.workspace_id = ` + s.bind(1) + ` AND r.repository_id = ` + s.bind(2)
	var workspaceLimit, repositoryLimit sql.NullInt64
	if err := tx.QueryRowContext(ctx, query, workspace, repository).Scan(&workspaceLimit, &repositoryLimit); err != nil {
		return errors.New("Cargo quota policy could not be read")
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
		} {
			if limit.repository && source.table != "registry_cargo_versions" && source.table != "registry_cargo_reservations" {
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
				return errors.New("Cargo quota usage could not be read")
			}
			if used > remaining {
				return ErrReservationQuota
			}
			remaining -= used
		}
	}
	return nil
}
