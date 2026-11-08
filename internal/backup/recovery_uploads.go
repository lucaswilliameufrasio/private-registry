package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
)

// InvalidateRestoredUploads is restricted to a caller-owned isolated recovery
// transaction. Incomplete claims expire; uploaded receipts retain their object
// references but cannot be published. The caller must roll back on errors.
// Reconciliation and an operator-approved release are not implemented here.
func InvalidateRestoredUploads(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, now time.Time) (int64, error) {
	if ctx == nil || tx == nil || now.IsZero() || (driver != config.SQLite && driver != config.Postgres) {
		return 0, errors.New("isolated upload recovery parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return 0, errors.New("isolated upload recovery requires a deadline")
	}
	bind := func(n int) string {
		if driver == config.Postgres {
			return fmt.Sprintf("$%d", n)
		}
		return "?"
	}
	var installationID string
	if err := tx.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&installationID); err != nil {
		return 0, errors.New("recovered installation identity could not be read")
	}
	if id, err := uuid.Parse(installationID); err != nil || id.String() != installationID {
		return 0, errors.New("recovered installation identity is invalid")
	}
	query := `UPDATE registry_generic_upload_sessions SET recovery_invalidated = 1, status = CASE WHEN status IN ('receiving', 'uploading') THEN 'expired' ELSE status END, upload_claim_id = NULL, updated_at = ` + bind(1) + ` WHERE status IN ('receiving', 'uploading', 'uploaded') AND recovery_invalidated = 0`
	updated, err := tx.ExecContext(ctx, query, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, errors.New("recovered uploads could not be invalidated; rollback required")
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return 0, errors.New("recovered uploads could not be counted; rollback required")
	}
	goUpdated, err := tx.ExecContext(ctx, `UPDATE registry_go_upload_sessions SET recovery_invalidated = 1, status = CASE WHEN status IN ('receiving', 'uploading') THEN 'expired' ELSE status END, upload_claim_id = NULL WHERE status IN ('receiving', 'uploading', 'uploaded') AND recovery_invalidated = 0`)
	if err != nil {
		return 0, errors.New("recovered Go uploads could not be invalidated; rollback required")
	}
	goCount, err := goUpdated.RowsAffected()
	if err != nil || goCount < 0 || count < 0 || goCount > int64(^uint64(0)>>1)-count {
		return 0, errors.New("recovered Go uploads could not be counted; rollback required")
	}
	count += goCount
	cargoUpdated, err := tx.ExecContext(ctx, `UPDATE registry_cargo_reservations SET recovery_invalidated = 1, status = CASE WHEN status IN ('reserved', 'uploading') THEN 'expired' ELSE status END, upload_claim_id = NULL WHERE status IN ('reserved', 'uploading', 'uploaded') AND recovery_invalidated = 0`)
	if err != nil {
		return 0, errors.New("recovered Cargo reservations could not be invalidated; rollback required")
	}
	cargoCount, err := cargoUpdated.RowsAffected()
	if err != nil || cargoCount < 0 || cargoCount > int64(^uint64(0)>>1)-count {
		return 0, errors.New("recovered Cargo reservations could not be counted; rollback required")
	}
	count += cargoCount
	npmUpdated, err := tx.ExecContext(ctx, `UPDATE registry_npm_reservations SET recovery_invalidated = 1, status = CASE WHEN status IN ('reserved', 'uploading') THEN 'expired' ELSE status END, upload_claim_id = NULL WHERE status IN ('reserved', 'uploading', 'uploaded') AND recovery_invalidated = 0`)
	if err != nil {
		return 0, errors.New("recovered npm reservations could not be invalidated; rollback required")
	}
	npmCount, err := npmUpdated.RowsAffected()
	if err != nil || npmCount < 0 || npmCount > int64(^uint64(0)>>1)-count {
		return 0, errors.New("recovered npm reservations could not be counted; rollback required")
	}
	count += npmCount
	pubUpdated, err := tx.ExecContext(ctx, `UPDATE registry_pub_reservations SET recovery_invalidated = 1, status = CASE WHEN status IN ('reserved', 'uploading') THEN 'expired' ELSE status END, upload_claim_id = NULL WHERE status IN ('reserved', 'uploading', 'uploaded') AND recovery_invalidated = 0`)
	if err != nil {
		return 0, errors.New("recovered Pub reservations could not be invalidated; rollback required")
	}
	pubCount, err := pubUpdated.RowsAffected()
	if err != nil || pubCount < 0 || pubCount > int64(^uint64(0)>>1)-count {
		return 0, errors.New("recovered Pub reservations could not be counted; rollback required")
	}
	count += pubCount
	if count > 0 {
		id, err := uuid.NewV7()
		if err != nil {
			return 0, errors.New("upload recovery audit identity could not be created; rollback required")
		}
		query := `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, actor_label, action, target_type, target_id, outcome, occurred_at) VALUES (` + bind(1) + `, NULL, 'operator', 'isolated-recovery', 'recovery.uploads.invalidated', 'installation', ` + bind(2) + `, 'succeeded', ` + bind(3) + `)`
		if _, err := tx.ExecContext(ctx, query, id.String(), installationID, now.UTC().Format(time.RFC3339Nano)); err != nil {
			return 0, errors.New("upload recovery audit could not be recorded; rollback required")
		}
	}
	return count, nil
}
