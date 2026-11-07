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

// HoldRestoredJobs must only run in an isolated recovery transaction. It
// preserves prior pending/running state, fences old leases and prevents claims.
// The caller must roll back on error. There is deliberately no automatic
// release: deciding which jobs can be retried requires a separate review.
func HoldRestoredJobs(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, now time.Time) (int64, error) {
	if ctx == nil || tx == nil || now.IsZero() || (driver != config.SQLite && driver != config.Postgres) {
		return 0, errors.New("isolated job recovery parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return 0, errors.New("isolated job recovery requires a deadline")
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
	query := `UPDATE registry_jobs SET recovery_previous_status = status, status = 'pending', lease_token = NULL, lease_until_ms = NULL, revision = revision + 1, updated_at_ms = ` + bind(1) + ` WHERE status IN ('pending', 'running') AND recovery_previous_status IS NULL`
	updated, err := tx.ExecContext(ctx, query, now.UTC().UnixMilli())
	if err != nil {
		return 0, errors.New("recovered jobs could not be held; rollback required")
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return 0, errors.New("recovered jobs could not be counted; rollback required")
	}
	if count > 0 {
		id, err := uuid.NewV7()
		if err != nil {
			return 0, errors.New("job recovery audit identity could not be created; rollback required")
		}
		query := `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, actor_label, action, target_type, target_id, outcome, occurred_at) VALUES (` + bind(1) + `, NULL, 'operator', 'isolated-recovery', 'recovery.jobs.held', 'installation', ` + bind(2) + `, 'succeeded', ` + bind(3) + `)`
		if _, err := tx.ExecContext(ctx, query, id.String(), installationID, now.UTC().Format(time.RFC3339Nano)); err != nil {
			return 0, errors.New("job recovery audit could not be recorded; rollback required")
		}
	}
	return count, nil
}
