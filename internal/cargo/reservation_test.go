package cargo_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/repositories"
)

func TestSQLiteCargoReservations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: root, DatabaseDriver: config.SQLite, DatabaseDSN: filepath.Join(root, "registry.sqlite"), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	exerciseReservations(t, ctx, db, config.SQLite)
}

func exerciseReservations(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver) {
	t.Helper()
	bind := func(n int) string {
		if driver == config.Postgres {
			return fmt.Sprintf("$%d", n)
		}
		return "?"
	}
	user, workspace, repository, grant := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	items := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (` + bind(1) + `, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at, logical_quota_bytes) VALUES (` + bind(1) + `, 'reservation', 'Reservation', ` + bind(2) + `, 'now', 100)`, []any{workspace, user}},
		{`INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, created_by, created_at, updated_at) VALUES (` + bind(1) + `, ` + bind(2) + `, 'owner', ` + bind(3) + `, 'now', 'now')`, []any{workspace, user, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format, logical_quota_bytes) VALUES (` + bind(1) + `, ` + bind(2) + `, 'cargo', 'Cargo', ` + bind(3) + `, 'now', 'now', 'cargo', 90)`, []any{repository, workspace, user}},
		{`INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (` + bind(1) + `, ` + bind(2) + `, ` + bind(3) + `, ` + bind(4) + `, 'publisher', ` + bind(5) + `, 'now')`, []any{grant, repository, workspace, user, user}},
	}
	for _, item := range items {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	repos, err := repositories.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := repos.IssueCargoWriteToken(ctx, user, workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := cargo.NewReservationService(db, repos, driver)
	if err != nil {
		t.Fatal(err)
	}
	frame := cargo.PublishFrame{Metadata: []byte(`{"name":"my-crate","vers":"1.0.0+first","deps":[],"features":{}}`), Size: 50, SHA256: strings.Repeat("a", 64)}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_cargo_reservation_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'cargo.reservation.created' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Reserve(ctx, credential.Bearer, workspace, repository, frame); err == nil {
			t.Fatal("reservation succeeded without audit")
		}
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_cargo_reservations WHERE repository_id = ?`, repository).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed reservation audit left a reservation: count=%d err=%v", count, err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_cargo_reservation_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	first, err := service.Reserve(ctx, credential.Bearer, workspace, repository, frame)
	if err != nil || first.ID == "" {
		t.Fatalf("reserve synthetic crate: %v", err)
	}
	again, err := service.Reserve(ctx, credential.Bearer, workspace, repository, frame)
	if err != nil || again != first {
		t.Fatalf("identical retry did not reconcile: %v", err)
	}
	var auditCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events WHERE action = 'cargo.reservation.created' AND target_id = `+bind(1), first.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("reservation audit not recorded exactly once: count=%d err=%v", auditCount, err)
	}
	conflicting := frame
	conflicting.Metadata = []byte(`{"name":"my_crate","vers":"1.0.0+second","deps":[],"features":{}}`)
	if _, err := service.Reserve(ctx, credential.Bearer, workspace, repository, conflicting); !errors.Is(err, cargo.ErrReservationConflict) {
		t.Fatalf("canonical identity collision accepted: %v", err)
	}
	conflicting.Metadata = []byte(`{"name":"my_crate","vers":"2.0.0","deps":[],"features":{}}`)
	if _, err := service.Reserve(ctx, credential.Bearer, workspace, repository, conflicting); !errors.Is(err, cargo.ErrReservationConflict) {
		t.Fatalf("equivalent name reserved under another version: %v", err)
	}
	overQuota := frame
	overQuota.Metadata = []byte(`{"name":"another","vers":"1.0.0","deps":[],"features":{}}`)
	if _, err := service.Reserve(ctx, credential.Bearer, workspace, repository, overQuota); !errors.Is(err, cargo.ErrReservationQuota) {
		t.Fatalf("quota oversubscription accepted: %v", err)
	}
	cancelFrame := cargo.PublishFrame{Metadata: []byte(`{"name":"cancel_fixture","vers":"1.0.0","deps":[],"features":{}}`), Size: 1, SHA256: strings.Repeat("f", 64)}
	cancelled, err := service.Reserve(ctx, credential.Bearer, workspace, repository, cancelFrame)
	if err != nil {
		t.Fatal(err)
	}
	otherCredential, err := repos.IssueCargoWriteToken(ctx, user, workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Cancel(ctx, otherCredential.Bearer, workspace, repository, cancelled.ID); !errors.Is(err, cargo.ErrReservationUnavailable) {
		t.Fatalf("different credential cancelled reservation: %v", err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_cargo_cancel_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'cargo.reservation.cancelled' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if err := service.Cancel(ctx, credential.Bearer, workspace, repository, cancelled.ID); err == nil {
			t.Fatal("cancellation succeeded without audit")
		}
		var state string
		if err := db.QueryRowContext(ctx, `SELECT status FROM registry_cargo_reservations WHERE reservation_id = ?`, cancelled.ID).Scan(&state); err != nil || state != "reserved" {
			t.Fatalf("failed cancellation audit changed reservation: %v", err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_cargo_cancel_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.Cancel(ctx, credential.Bearer, workspace, repository, cancelled.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.Cancel(ctx, credential.Bearer, workspace, repository, cancelled.ID); err != nil {
		t.Fatalf("repeated cancellation failed: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events WHERE action = 'cargo.reservation.cancelled' AND target_id = `+bind(1), cancelled.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("cancellation audit not recorded exactly once: count=%d err=%v", auditCount, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET status = 'reserved' WHERE reservation_id = `+bind(1), cancelled.ID); err == nil {
		t.Fatal("cancelled Cargo reservation was reactivated")
	}
	quotaResults := make(chan error, 2)
	for _, name := range []string{"parallel_a", "parallel_b"} {
		go func(name string) {
			candidate := cargo.PublishFrame{Metadata: []byte(fmt.Sprintf(`{"name":%q,"vers":"1.0.0","deps":[],"features":{}}`, name)), Size: 30, SHA256: strings.Repeat("b", 64)}
			_, err := service.Reserve(ctx, credential.Bearer, workspace, repository, candidate)
			quotaResults <- err
		}(name)
	}
	assertReservationRace(t, quotaResults, cargo.ErrReservationQuota)
	identityResults := make(chan error, 2)
	for _, digest := range []string{strings.Repeat("c", 64), strings.Repeat("d", 64)} {
		go func(digest string) {
			candidate := cargo.PublishFrame{Metadata: []byte(`{"name":"racer","vers":"1.0.0","deps":[],"features":{}}`), Size: 5, SHA256: digest}
			_, err := service.Reserve(ctx, credential.Bearer, workspace, repository, candidate)
			identityResults <- err
		}(digest)
	}
	assertReservationRace(t, identityResults, cargo.ErrReservationConflict)
	nameResults := make(chan error, 2)
	for _, candidate := range []struct{ name, version string }{{"race-name", "1.0.0"}, {"race_name", "2.0.0"}} {
		go func(name, version string) {
			frame := cargo.PublishFrame{Metadata: []byte(fmt.Sprintf(`{"name":%q,"vers":%q,"deps":[],"features":{}}`, name, version)), Size: 2, SHA256: strings.Repeat("e", 64)}
			_, err := service.Reserve(ctx, credential.Bearer, workspace, repository, frame)
			nameResults <- err
		}(candidate.name, candidate.version)
	}
	assertReservationRace(t, nameResults, cargo.ErrReservationConflict)
	if err := repos.RevokeCargoWriteToken(ctx, user, credential.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Reserve(ctx, credential.Bearer, workspace, repository, frame); !errors.Is(err, repositories.ErrCargoWriteTokenUnavailable) {
		t.Fatalf("revoked credential reconciled reservation: %v", err)
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM registry_cargo_reservations WHERE reservation_id = `+bind(1), first.ID).Scan(&status); err != nil || status != "reserved" {
		t.Fatalf("reservation state changed unexpectedly: %v", err)
	}
	future := time.Now().UTC().Add(48 * time.Hour)
	if count, err := service.ExpireUploadBatch(ctx, future, 2); err != nil || count != 2 {
		t.Fatalf("first bounded expiration failed: count=%d err=%v", count, err)
	}
	if count, err := service.ExpireUploadBatch(ctx, future, 2); err != nil || count != 2 {
		t.Fatalf("second bounded expiration failed: count=%d err=%v", count, err)
	}
	if count, err := service.ExpireUploadBatch(ctx, future, 2); err != nil || count != 0 {
		t.Fatalf("expiration was not idempotent: count=%d err=%v", count, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET status = 'reserved' WHERE reservation_id = `+bind(1), first.ID); err == nil {
		t.Fatal("expired Cargo reservation was reactivated")
	}
}

func assertReservationRace(t *testing.T, results <-chan error, expected error) {
	t.Helper()
	var successes, rejected int
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, expected) {
			rejected++
		} else {
			t.Fatalf("unexpected reservation race result: %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("reservation race successes=%d rejected=%d", successes, rejected)
	}
}
