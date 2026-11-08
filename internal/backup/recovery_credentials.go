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

type InvalidatedCredentials struct {
	Sessions         int64
	PersonalTokens   int64
	CargoWriteTokens int64
	NPMWriteTokens   int64
	DownloadTickets  int64
}

// InvalidateRestoredCredentials mutates the caller's transaction and must ONLY
// be used on an offline, isolated recovery database controlled by the caller.
// The caller owns rollback on every error and commits only after all recovery
// checks succeed. It is not wired to serve or any live administrative route.
// The explicit schema check fails closed if new migrations may add credentials
// this implementation does not know how to invalidate.
func InvalidateRestoredCredentials(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, now time.Time) (InvalidatedCredentials, error) {
	if ctx == nil || tx == nil || now.IsZero() || (driver != config.SQLite && driver != config.Postgres) {
		return InvalidatedCredentials{}, errors.New("isolated credential recovery parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return InvalidatedCredentials{}, errors.New("isolated credential recovery requires a deadline")
	}
	var count, minimum, maximum int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(MIN(version_id), 0), COALESCE(MAX(version_id), 0) FROM registry_migration_checksums`).Scan(&count, &minimum, &maximum); err != nil || count != 28 || minimum != 1 || maximum != 28 {
		return InvalidatedCredentials{}, errors.New("recovered database schema is not supported for credential invalidation")
	}
	bind := func(index int) string {
		if driver == config.Postgres {
			return fmt.Sprintf("$%d", index)
		}
		return "?"
	}
	var installationID string
	if err := tx.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&installationID); err != nil {
		return InvalidatedCredentials{}, errors.New("recovered installation identity could not be read")
	}
	if id, err := uuid.Parse(installationID); err != nil || id.String() != installationID {
		return InvalidatedCredentials{}, errors.New("recovered installation identity is invalid")
	}
	var result InvalidatedCredentials
	queries := []struct {
		query string
		args  []any
		count *int64
	}{
		{`UPDATE registry_auth_sessions SET revoked_at = ` + bind(1) + ` WHERE revoked_at IS NULL`, []any{now.UTC().Format(time.RFC3339Nano)}, &result.Sessions},
		{`UPDATE registry_personal_read_tokens SET revoked_at_ms = ` + bind(1) + ` WHERE revoked_at_ms IS NULL`, []any{now.UTC().UnixMilli()}, &result.PersonalTokens},
		{`UPDATE registry_cargo_write_tokens SET revoked_at_ms = ` + bind(1) + ` WHERE revoked_at_ms IS NULL`, []any{now.UTC().UnixMilli()}, &result.CargoWriteTokens},
		{`UPDATE registry_npm_write_tokens SET revoked_at_ms = ` + bind(1) + ` WHERE revoked_at_ms IS NULL`, []any{now.UTC().UnixMilli()}, &result.NPMWriteTokens},
		// Ticket revocations require a human revoked_by value. Delete capability
		// records in the recovered copy instead of falsely attributing revocation.
		{`DELETE FROM registry_generic_download_tickets`, nil, &result.DownloadTickets},
	}
	for _, operation := range queries {
		changed, err := tx.ExecContext(ctx, operation.query, operation.args...)
		if err != nil {
			return InvalidatedCredentials{}, errors.New("recovered credentials could not be invalidated; rollback required")
		}
		*operation.count, err = changed.RowsAffected()
		if err != nil {
			return InvalidatedCredentials{}, errors.New("recovered credential invalidation could not be counted; rollback required")
		}
	}
	if result.Sessions+result.PersonalTokens+result.CargoWriteTokens+result.NPMWriteTokens+result.DownloadTickets > 0 {
		id, err := uuid.NewV7()
		if err != nil {
			return InvalidatedCredentials{}, errors.New("recovery audit identity could not be created; rollback required")
		}
		query := `INSERT INTO registry_audit_events (event_id, actor_user_id, actor_type, actor_label, action, target_type, target_id, outcome, occurred_at) VALUES (` + bind(1) + `, NULL, 'operator', 'isolated-recovery', 'recovery.credentials.invalidated', 'installation', ` + bind(2) + `, 'succeeded', ` + bind(3) + `)`
		if _, err := tx.ExecContext(ctx, query, id.String(), installationID, now.UTC().Format(time.RFC3339Nano)); err != nil {
			return InvalidatedCredentials{}, errors.New("credential recovery audit could not be recorded; rollback required")
		}
	}
	return result, nil
}
