package cargo

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SetYanked changes only the published index flag, preserving the immutable
// archive so existing lockfiles can still download it. A current Cargo write
// credential and publisher grant are required in the same transaction.
func (s *ReservationService) SetYanked(ctx context.Context, bearer, workspace, repository, name, version string, yanked bool) error {
	if s == nil || ctx == nil {
		return ErrPackageUnavailable
	}
	identity, err := NameIdentity(name)
	if err != nil {
		return ErrPackageUnavailable
	}
	versionKey, err := VersionIdentity(version)
	if err != nil || versionKey != version {
		return ErrPackageUnavailable
	}
	return s.repositories.WithCargoWriteTokenTransaction(ctx, bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
		query := `SELECT v.cargo_version_id, v.yanked FROM registry_cargo_versions v JOIN registry_cargo_packages p ON p.package_id = v.package_id AND p.workspace_id = v.workspace_id AND p.repository_id = v.repository_id JOIN registry_cargo_publications cp ON cp.cargo_version_id = v.cargo_version_id AND cp.workspace_id = v.workspace_id AND cp.repository_id = v.repository_id WHERE v.workspace_id = ` + s.bind(1) + ` AND v.repository_id = ` + s.bind(2) + ` AND p.name_identity = ` + s.bind(3) + ` AND lower(p.name) = ` + s.bind(4) + ` AND v.version_identity = ` + s.bind(5)
		var versionID string
		var previous int
		if err := tx.QueryRowContext(ctx, query, workspace, repository, identity, strings.ToLower(name), versionKey).Scan(&versionID, &previous); errors.Is(err, sql.ErrNoRows) {
			return ErrPackageUnavailable
		} else if err != nil {
			return errors.New("Cargo yank state could not be read")
		}
		value := 0
		action := "cargo.version.unyanked"
		if yanked {
			value = 1
			action = "cargo.version.yanked"
		}
		if previous == value {
			return nil
		}
		query = `UPDATE registry_cargo_versions SET yanked = ` + s.bind(1) + ` WHERE cargo_version_id = ` + s.bind(2) + ` AND yanked = ` + s.bind(3)
		result, err := tx.ExecContext(ctx, query, value, versionID, previous)
		if err != nil {
			return errors.New("Cargo yank state could not be changed")
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return errors.New("Cargo yank state changed concurrently")
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return errors.New("Cargo yank audit identity could not be created")
		}
		query = `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, action, target_type, target_id, outcome, occurred_at) VALUES (` + s.bind(1) + `, ` + s.bind(2) + `, 'user', ` + s.bind(3) + `, 'cargo_version', ` + s.bind(4) + `, 'succeeded', ` + s.bind(5) + `)`
		if _, err := tx.ExecContext(ctx, query, auditID.String(), actor, action, versionID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return errors.New("Cargo yank state could not be audited")
		}
		return nil
	})
}
