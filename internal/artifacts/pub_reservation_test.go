package artifacts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/npm"
	"private-registry/internal/pub"
	"private-registry/internal/repositories"
)

func TestSQLitePubReservationQuotaAndLifecycle(t *testing.T) {
	fixture := newArtifactFixture(t)
	exercisePubReservationQuotaAndLifecycle(t, fixture.service, fixture.db, config.SQLite, fixture.userIDs["publisher"], fixture.workspaceID, fixture.repositoryID)
}

func exercisePubReservationQuotaAndLifecycle(t *testing.T, artifacts *Service, db *sql.DB, driver config.DatabaseDriver, actor, workspace, genericRepository string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p := func(n int) string {
		if driver == config.Postgres {
			return fmt.Sprintf("$%d", n)
		}
		return "?"
	}
	var owner, created string
	if err := db.QueryRowContext(ctx, `SELECT created_by, created_at FROM registry_repositories WHERE repository_id = `+p(1), genericRepository).Scan(&owner, &created); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_workspaces SET logical_quota_bytes = 10 WHERE workspace_id = `+p(1), workspace); err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	query := `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'pub-reservation', 'pub', ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, 'pub')`
	if _, err := db.ExecContext(ctx, query, repository, workspace, owner, created, created); err != nil {
		t.Fatal(err)
	}
	query = `INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, 'publisher', ` + p(5) + `, ` + p(6) + `)`
	if _, err := db.ExecContext(ctx, query, uuid.NewString(), repository, workspace, actor, owner, created); err != nil {
		t.Fatal(err)
	}
	token, err := artifacts.repositories.IssuePubWriteToken(ctx, actor, workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := pub.NewReservationService(db, artifacts.repositories, driver)
	if err != nil {
		t.Fatal(err)
	}
	request := pub.ReservationRequest{Name: "fixture", Version: "1.0.0+first", TarballSHA256: strings.Repeat("a", 64), TarballSize: 7, MetadataSHA256: strings.Repeat("b", 64)}
	for _, invalid := range []pub.ReservationRequest{
		{Name: "BAD", Version: request.Version, TarballSHA256: request.TarballSHA256, TarballSize: 7, MetadataSHA256: request.MetadataSHA256},
		{Name: request.Name, Version: "1.0", TarballSHA256: request.TarballSHA256, TarballSize: 7, MetadataSHA256: request.MetadataSHA256},
		{Name: request.Name, Version: request.Version, TarballSHA256: strings.Repeat("A", 64), TarballSize: 7, MetadataSHA256: request.MetadataSHA256},
		{Name: request.Name, Version: request.Version, TarballSHA256: request.TarballSHA256, TarballSize: 0, MetadataSHA256: request.MetadataSHA256},
	} {
		if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, invalid); err == nil {
			t.Fatal("invalid pub reservation was accepted")
		}
	}
	if _, err := service.Reserve(ctx, token.Bearer, workspace, uuid.NewString(), request); !errors.Is(err, repositories.ErrPubWriteTokenUnavailable) {
		t.Fatalf("cross-repository pub reservation accepted: %v", err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_pub_reservation_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'pub.reservation.created' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, request); err == nil {
			t.Fatal("pub reservation succeeded without audit")
		}
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_pub_reservations WHERE repository_id = ?`, repository).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed audit left pub reservation: count=%d err=%v", count, err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_pub_reservation_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	reservation, err := service.Reserve(ctx, token.Bearer, workspace, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := service.Reserve(ctx, token.Bearer, workspace, repository, request)
	if err != nil || retry != reservation {
		t.Fatalf("identical pub reservation retry failed: %v", err)
	}
	var auditCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events WHERE action = 'pub.reservation.created' AND target_id = `+p(1), reservation.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("pub reservation audit is not exactly once: count=%d err=%v", auditCount, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_pub_reservations SET tarball_size = 1 WHERE reservation_id = `+p(1), reservation.ID); err == nil {
		t.Fatal("pub reservation identity was mutable")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM registry_pub_reservations WHERE reservation_id = `+p(1), reservation.ID); err == nil {
		t.Fatal("pub reservation history was deleted")
	}
	changed := request
	changed.Version = "1.0.0+other"
	if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, changed); !errors.Is(err, pub.ErrReservationConflict) {
		t.Fatalf("different pub reservation with same identity accepted: %v", err)
	}
	if _, err := artifacts.StartUpload(ctx, actor, workspace, genericRepository, requestFor("pub-reserved", "v1", "file", []byte("four"))); !errors.Is(err, ErrLogicalQuotaExceeded) {
		t.Fatalf("pub reservation not counted by generic quota: %v", err)
	}
	cargoRepository := uuid.NewString()
	query = `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'cargo-pub-reservation', 'Cargo', ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, 'cargo')`
	if _, err := db.ExecContext(ctx, query, cargoRepository, workspace, owner, created, created); err != nil {
		t.Fatal(err)
	}
	query = `INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, 'publisher', ` + p(5) + `, ` + p(6) + `)`
	if _, err := db.ExecContext(ctx, query, uuid.NewString(), cargoRepository, workspace, actor, owner, created); err != nil {
		t.Fatal(err)
	}
	cargoToken, err := artifacts.repositories.IssueCargoWriteToken(ctx, actor, workspace, cargoRepository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cargoService, err := cargo.NewReservationService(db, artifacts.repositories, driver)
	if err != nil {
		t.Fatal(err)
	}
	frame := cargo.PublishFrame{Metadata: []byte(`{"name":"fixture","vers":"1.0.0","deps":[],"features":{}}`), Size: 4, SHA256: strings.Repeat("c", 64)}
	if _, err := cargoService.Reserve(ctx, cargoToken.Bearer, workspace, cargoRepository, frame); !errors.Is(err, cargo.ErrReservationQuota) {
		t.Fatalf("pub reservation not counted by Cargo quota: %v", err)
	}
	npmRepository := uuid.NewString()
	query = `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'npm-pub-reservation', 'npm', ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, 'npm')`
	if _, err := db.ExecContext(ctx, query, npmRepository, workspace, owner, created, created); err != nil {
		t.Fatal(err)
	}
	query = `INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, 'publisher', ` + p(5) + `, ` + p(6) + `)`
	if _, err := db.ExecContext(ctx, query, uuid.NewString(), npmRepository, workspace, actor, owner, created); err != nil {
		t.Fatal(err)
	}
	npmToken, err := artifacts.repositories.IssueNPMWriteToken(ctx, actor, workspace, npmRepository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	npmService, err := npm.NewReservationService(db, artifacts.repositories, driver)
	if err != nil {
		t.Fatal(err)
	}
	npmRequest := npm.ReservationRequest{Name: "fixture", Version: "1.0.0", TarballSHA256: strings.Repeat("c", 64), TarballSize: 4, MetadataSHA256: strings.Repeat("d", 64)}
	if _, err := npmService.Reserve(ctx, npmToken.Bearer, workspace, npmRepository, npmRequest); !errors.Is(err, npm.ErrReservationQuota) {
		t.Fatalf("Pub reservation not counted by npm quota: %v", err)
	}
	other := request
	other.Name = "second"
	other.TarballSize = 4
	if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, other); !errors.Is(err, pub.ErrReservationQuota) {
		t.Fatalf("pub reservation exceeded workspace quota: %v", err)
	}
	otherToken, err := artifacts.repositories.IssuePubWriteToken(ctx, actor, workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Cancel(ctx, otherToken.Bearer, workspace, repository, reservation.ID); !errors.Is(err, pub.ErrReservationUnavailable) {
		t.Fatalf("different credential cancelled pub reservation: %v", err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_pub_cancel_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'pub.reservation.cancelled' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if err := service.Cancel(ctx, token.Bearer, workspace, repository, reservation.ID); err == nil {
			t.Fatal("pub cancellation succeeded without audit")
		}
		var status string
		if err := db.QueryRowContext(ctx, `SELECT status FROM registry_pub_reservations WHERE reservation_id = ?`, reservation.ID).Scan(&status); err != nil || status != "reserved" {
			t.Fatalf("failed audit changed pub reservation: %v", err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_pub_cancel_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.Cancel(ctx, token.Bearer, workspace, repository, reservation.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events WHERE action = 'pub.reservation.cancelled' AND target_id = `+p(1), reservation.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("pub cancellation audit is not exactly once: count=%d err=%v", auditCount, err)
	}
	if err := service.Cancel(ctx, token.Bearer, workspace, repository, reservation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := artifacts.StartUpload(ctx, actor, workspace, genericRepository, requestFor("pub-reserved", "v2", "file", []byte("four"))); err != nil {
		t.Fatalf("cancelled pub reservation did not release quota: %v", err)
	}
	packageID := uuid.NewString()
	query = `INSERT INTO registry_pub_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, 'published', ` + p(4) + `, ` + p(5) + `)`
	if _, err := db.ExecContext(ctx, query, packageID, workspace, repository, actor, created); err != nil {
		t.Fatal(err)
	}
	query = `INSERT INTO registry_pub_versions (pub_version_id, workspace_id, repository_id, package_id, version, version_identity, manifest, tarball_sha256, tarball_size, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, '1.0.0+old', '1.0.0', '{}', ` + p(5) + `, 1, ` + p(6) + `, ` + p(7) + `)`
	if _, err := db.ExecContext(ctx, query, uuid.NewString(), workspace, repository, packageID, strings.Repeat("e", 64), actor, created); err != nil {
		t.Fatal(err)
	}
	published := request
	published.Name = "published"
	if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, published); !errors.Is(err, pub.ErrReservationConflict) {
		t.Fatalf("published pub identity was reserved again: %v", err)
	}
	concurrent := request
	concurrent.Name = "concurrent"
	concurrent.TarballSize = 2
	type reservationResult struct {
		reservation pub.Reservation
		err         error
	}
	results := make(chan reservationResult, 2)
	for range 2 {
		go func() {
			item, err := service.Reserve(ctx, token.Bearer, workspace, repository, concurrent)
			results <- reservationResult{item, err}
		}()
	}
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.reservation.ID == "" || first.reservation != second.reservation {
		t.Fatalf("concurrent identical pub reservations were not reconciled: %v %v", first.err, second.err)
	}
	if err := service.Cancel(ctx, token.Bearer, workspace, repository, first.reservation.ID); err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{strings.Repeat("c", 64), strings.Repeat("d", 64)} {
		go func(digest string) {
			item := concurrent
			item.Name = "competing"
			item.TarballSHA256 = digest
			reservation, err := service.Reserve(ctx, token.Bearer, workspace, repository, item)
			results <- reservationResult{reservation, err}
		}(digest)
	}
	first, second = <-results, <-results
	if !((first.err == nil && errors.Is(second.err, pub.ErrReservationConflict)) || (second.err == nil && errors.Is(first.err, pub.ErrReservationConflict))) {
		t.Fatalf("competing pub reservations did not select one winner: %v %v", first.err, second.err)
	}
	if err := artifacts.repositories.RevokeRepositoryRole(ctx, owner, workspace, repository, actor, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, other); !errors.Is(err, repositories.ErrPubWriteTokenUnavailable) {
		t.Fatalf("revoked publisher reserved pub identity: %v", err)
	}
}
