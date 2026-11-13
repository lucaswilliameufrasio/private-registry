package artifacts

import (
	"context"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/npm"
	"private-registry/internal/repositories"
)

func TestSQLiteNPMReservationQuotaAndLifecycle(t *testing.T) {
	fixture := newArtifactFixture(t)
	exerciseNPMReservationQuotaAndLifecycle(t, fixture.service, fixture.db, config.SQLite, fixture.userIDs["publisher"], fixture.workspaceID, fixture.repositoryID)
}

func exerciseNPMReservationQuotaAndLifecycle(t *testing.T, artifacts *Service, db *sql.DB, driver config.DatabaseDriver, actor, workspace, genericRepository string) {
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
	query := `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'npm-reservation', 'npm', ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, 'npm')`
	if _, err := db.ExecContext(ctx, query, repository, workspace, owner, created, created); err != nil {
		t.Fatal(err)
	}
	query = `INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, 'publisher', ` + p(5) + `, ` + p(6) + `)`
	if _, err := db.ExecContext(ctx, query, uuid.NewString(), repository, workspace, actor, owner, created); err != nil {
		t.Fatal(err)
	}
	token, err := artifacts.repositories.IssueNPMWriteToken(ctx, actor, workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := npm.NewReservationService(db, artifacts.repositories, driver)
	if err != nil {
		t.Fatal(err)
	}
	request := npm.ReservationRequest{Name: "fixture", Version: "1.0.0+first", TarballSHA256: strings.Repeat("a", 64), TarballSize: 7, MetadataSHA256: strings.Repeat("b", 64)}
	for _, invalid := range []npm.ReservationRequest{
		{Name: "BAD", Version: request.Version, TarballSHA256: request.TarballSHA256, TarballSize: 7, MetadataSHA256: request.MetadataSHA256},
		{Name: request.Name, Version: "1.0", TarballSHA256: request.TarballSHA256, TarballSize: 7, MetadataSHA256: request.MetadataSHA256},
		{Name: request.Name, Version: request.Version, TarballSHA256: strings.Repeat("A", 64), TarballSize: 7, MetadataSHA256: request.MetadataSHA256},
		{Name: request.Name, Version: request.Version, TarballSHA256: request.TarballSHA256, TarballSize: 0, MetadataSHA256: request.MetadataSHA256},
	} {
		if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, invalid); err == nil {
			t.Fatal("invalid npm reservation was accepted")
		}
	}
	if _, err := service.Reserve(ctx, token.Bearer, workspace, uuid.NewString(), request); !errors.Is(err, repositories.ErrNPMWriteTokenUnavailable) {
		t.Fatalf("cross-repository npm reservation accepted: %v", err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_npm_reservation_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'npm.reservation.created' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, request); err == nil {
			t.Fatal("npm reservation succeeded without audit")
		}
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_npm_reservations WHERE repository_id = ?`, repository).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed audit left npm reservation: count=%d err=%v", count, err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_npm_reservation_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	reservation, err := service.Reserve(ctx, token.Bearer, workspace, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := service.Reserve(ctx, token.Bearer, workspace, repository, request)
	if err != nil || retry != reservation {
		t.Fatalf("identical npm reservation retry failed: %v", err)
	}
	var auditCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events WHERE action = 'npm.reservation.created' AND target_id = `+p(1), reservation.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("npm reservation audit is not exactly once: count=%d err=%v", auditCount, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_npm_reservations SET tarball_size = 1 WHERE reservation_id = `+p(1), reservation.ID); err == nil {
		t.Fatal("npm reservation identity was mutable")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM registry_npm_reservations WHERE reservation_id = `+p(1), reservation.ID); err == nil {
		t.Fatal("npm reservation history was deleted")
	}
	changed := request
	changed.Version = "1.0.0+other"
	if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, changed); !errors.Is(err, npm.ErrReservationConflict) {
		t.Fatalf("different npm reservation with same identity accepted: %v", err)
	}
	if _, err := artifacts.StartUpload(ctx, actor, workspace, genericRepository, requestFor("npm-reserved", "v1", "file", []byte("four"))); !errors.Is(err, ErrLogicalQuotaExceeded) {
		t.Fatalf("npm reservation not counted by generic quota: %v", err)
	}
	cargoRepository := uuid.NewString()
	query = `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'cargo-npm-reservation', 'Cargo', ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, 'cargo')`
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
		t.Fatalf("npm reservation not counted by Cargo quota: %v", err)
	}
	other := request
	other.Name = "second"
	other.TarballSize = 4
	if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, other); !errors.Is(err, npm.ErrReservationQuota) {
		t.Fatalf("npm reservation exceeded workspace quota: %v", err)
	}
	otherToken, err := artifacts.repositories.IssueNPMWriteToken(ctx, actor, workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Cancel(ctx, otherToken.Bearer, workspace, repository, reservation.ID); !errors.Is(err, npm.ErrReservationUnavailable) {
		t.Fatalf("different credential cancelled npm reservation: %v", err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_npm_cancel_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'npm.reservation.cancelled' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if err := service.Cancel(ctx, token.Bearer, workspace, repository, reservation.ID); err == nil {
			t.Fatal("npm cancellation succeeded without audit")
		}
		var status string
		if err := db.QueryRowContext(ctx, `SELECT status FROM registry_npm_reservations WHERE reservation_id = ?`, reservation.ID).Scan(&status); err != nil || status != "reserved" {
			t.Fatalf("failed audit changed npm reservation: %v", err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_npm_cancel_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.Cancel(ctx, token.Bearer, workspace, repository, reservation.ID); err != nil {
		t.Fatal(err)
	}
	pubRepository, pubPackage := uuid.NewString(), uuid.NewString()
	query = `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'pub-quota', 'Pub', ` + p(3) + `, ` + p(4) + `, ` + p(5) + `, 'pub')`
	if _, err := db.ExecContext(ctx, query, pubRepository, workspace, owner, created, created); err != nil {
		t.Fatal(err)
	}
	query = `INSERT INTO registry_pub_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, 'fixture', ` + p(4) + `, ` + p(5) + `)`
	if _, err := db.ExecContext(ctx, query, pubPackage, workspace, pubRepository, actor, created); err != nil {
		t.Fatal(err)
	}
	query = `INSERT INTO registry_pub_versions (pub_version_id, workspace_id, repository_id, package_id, version, version_identity, manifest, tarball_sha256, tarball_size, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, '1.0.0', '1.0.0', 'fixture', ` + p(5) + `, 7, ` + p(6) + `, ` + p(7) + `)`
	if _, err := db.ExecContext(ctx, query, uuid.NewString(), workspace, pubRepository, pubPackage, strings.Repeat("f", 64), actor, created); err != nil {
		t.Fatal(err)
	}
	if _, err := artifacts.StartUpload(ctx, actor, workspace, genericRepository, requestFor("pub-quota", "v1", "file", []byte("four"))); !errors.Is(err, ErrLogicalQuotaExceeded) {
		t.Fatalf("Pub version not counted by generic quota: %v", err)
	}
	if _, err := cargoService.Reserve(ctx, cargoToken.Bearer, workspace, cargoRepository, frame); !errors.Is(err, cargo.ErrReservationQuota) {
		t.Fatalf("Pub version not counted by Cargo quota: %v", err)
	}
	if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, other); !errors.Is(err, npm.ErrReservationQuota) {
		t.Fatalf("Pub version not counted by npm quota: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_workspaces SET logical_quota_bytes = 17 WHERE workspace_id = `+p(1), workspace); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events WHERE action = 'npm.reservation.cancelled' AND target_id = `+p(1), reservation.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("npm cancellation audit is not exactly once: count=%d err=%v", auditCount, err)
	}
	if err := service.Cancel(ctx, token.Bearer, workspace, repository, reservation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := artifacts.StartUpload(ctx, actor, workspace, genericRepository, requestFor("npm-reserved", "v2", "file", []byte("four"))); err != nil {
		t.Fatalf("cancelled npm reservation did not release quota: %v", err)
	}
	packageID := uuid.NewString()
	query = `INSERT INTO registry_npm_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, 'published', ` + p(4) + `, ` + p(5) + `)`
	if _, err := db.ExecContext(ctx, query, packageID, workspace, repository, actor, created); err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512([]byte("synthetic"))
	query = `INSERT INTO registry_npm_versions (npm_version_id, workspace_id, repository_id, package_id, version, version_identity, manifest, tarball_sha256, tarball_size, integrity, created_by, created_at) VALUES (` + p(1) + `, ` + p(2) + `, ` + p(3) + `, ` + p(4) + `, '1.0.0+old', '1.0.0', '{}', ` + p(5) + `, 1, ` + p(6) + `, ` + p(7) + `, ` + p(8) + `)`
	if _, err := db.ExecContext(ctx, query, uuid.NewString(), workspace, repository, packageID, strings.Repeat("e", 64), "sha512-"+base64.StdEncoding.EncodeToString(digest[:]), actor, created); err != nil {
		t.Fatal(err)
	}
	published := request
	published.Name = "published"
	if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, published); !errors.Is(err, npm.ErrReservationConflict) {
		t.Fatalf("published npm identity was reserved again: %v", err)
	}
	concurrent := request
	concurrent.Name = "concurrent"
	concurrent.TarballSize = 2
	type reservationResult struct {
		reservation npm.Reservation
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
		t.Fatalf("concurrent identical npm reservations were not reconciled: %v %v", first.err, second.err)
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
	if !((first.err == nil && errors.Is(second.err, npm.ErrReservationConflict)) || (second.err == nil && errors.Is(first.err, npm.ErrReservationConflict))) {
		t.Fatalf("competing npm reservations did not select one winner: %v %v", first.err, second.err)
	}
	if count, err := service.ExpireUploadBatch(ctx, time.Now().UTC().Add(time.Hour), 1); err != nil || count != 1 {
		t.Fatalf("npm reservation expiration failed: count=%d err=%v", count, err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		count, err := service.ExpireUploadBatch(ctx, time.Now().UTC().Add(time.Hour), 1)
		if err != nil || count < 0 || count > 1 {
			t.Fatalf("npm expiration exceeded its batch bound: count=%d err=%v", count, err)
		}
		if count == 0 {
			break
		}
		if attempt == 2 {
			t.Fatal("npm expiration did not converge")
		}
	}
	winner := first.reservation
	if first.err != nil {
		winner = second.reservation
	}
	var expiredStatus string
	if err := db.QueryRowContext(ctx, `SELECT status FROM registry_npm_reservations WHERE reservation_id = `+p(1), winner.ID).Scan(&expiredStatus); err != nil || expiredStatus != "expired" {
		t.Fatalf("npm reservation did not expire: status=%q err=%v", expiredStatus, err)
	}
	if err := artifacts.repositories.RevokeRepositoryRole(ctx, owner, workspace, repository, actor, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Reserve(ctx, token.Bearer, workspace, repository, other); !errors.Is(err, repositories.ErrNPMWriteTokenUnavailable) {
		t.Fatalf("revoked publisher reserved npm identity: %v", err)
	}
}
