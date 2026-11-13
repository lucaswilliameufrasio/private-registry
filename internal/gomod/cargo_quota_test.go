package gomod

import (
	"context"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
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
	"private-registry/internal/npm"
	"private-registry/internal/pub"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

func exerciseGoQuotaCountsCargoReceipt(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver, root string) {
	t.Helper()
	bind := func(n int) string {
		if driver == config.Postgres {
			return fmt.Sprintf("$%d", n)
		}
		return "?"
	}
	user, workspace, goRepo, cargoRepo, grant := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	items := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (` + bind(1) + `, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at, logical_quota_bytes) VALUES (` + bind(1) + `, 'go-cargo-receipt-quota', 'Quota', ` + bind(2) + `, 'now', 10)`, []any{workspace, user}},
		{`INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, created_by, created_at, updated_at) VALUES (` + bind(1) + `, ` + bind(2) + `, 'owner', ` + bind(3) + `, 'now', 'now')`, []any{workspace, user, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + bind(1) + `, ` + bind(2) + `, 'go', 'Go', ` + bind(3) + `, 'now', 'now', 'go')`, []any{goRepo, workspace, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + bind(1) + `, ` + bind(2) + `, 'cargo', 'Cargo', ` + bind(3) + `, 'now', 'now', 'cargo')`, []any{cargoRepo, workspace, user}},
		{`INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (` + bind(1) + `, ` + bind(2) + `, ` + bind(3) + `, ` + bind(4) + `, 'publisher', ` + bind(5) + `, 'now')`, []any{grant, cargoRepo, workspace, user, user}},
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
	token, err := repos.IssueCargoWriteToken(ctx, user, workspace, cargoRepo, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reservationService, err := cargo.NewReservationService(db, repos, driver)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := reservationService.Reserve(ctx, token.Bearer, workspace, cargoRepo, cargo.PublishFrame{Metadata: []byte(`{"name":"fixture","vers":"1.0.0","deps":[],"features":{}}`), Size: 7, SHA256: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "quota-go-staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	objects, err := storage.NewFileSystem(filepath.Join(root, "quota-go-objects"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(db, driver, repos, objects, Options{StagingDirectory: staging, MaxZipBytes: 1024, MaxFiles: 10, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"reserved", "uploading", "uploaded", "published"} {
		if state == "uploading" {
			if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET status = 'uploading', upload_claim_id = `+bind(1)+` WHERE reservation_id = `+bind(2), uuid.NewString(), reservation.ID); err != nil {
				t.Fatal(err)
			}
		}
		if state == "uploaded" {
			if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET status = 'uploaded', upload_claim_id = NULL, object_verified = 1, index_entry = '{}' WHERE reservation_id = `+bind(1), reservation.ID); err != nil {
				t.Fatal(err)
			}
		}
		if state == "published" {
			if _, err := reservationService.PublishReceipt(ctx, token.Bearer, workspace, cargoRepo, reservation.ID); err != nil {
				t.Fatalf("publish synthetic Cargo receipt: %v", err)
			}
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.checkReservationQuota(ctx, tx, workspace, goRepo, 4); !errors.Is(err, ErrQuotaExceeded) {
			_ = tx.Rollback()
			t.Fatalf("Cargo %s did not count towards Go quota: %v", state, err)
		}
		if err := service.checkReservationQuota(ctx, tx, workspace, goRepo, 3); err != nil {
			_ = tx.Rollback()
			t.Fatalf("available Go quota rejected for Cargo %s: %v", state, err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_workspaces SET logical_quota_bytes = 17 WHERE workspace_id = `+bind(1), workspace); err != nil {
		t.Fatal(err)
	}
	npmRepo, pkg := uuid.NewString(), uuid.NewString()
	query := `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + bind(1) + `, ` + bind(2) + `, 'npm', 'npm', ` + bind(3) + `, 'now', 'now', 'npm')`
	if _, err := db.ExecContext(ctx, query, npmRepo, workspace, user); err != nil {
		t.Fatal(err)
	}
	query = `INSERT INTO registry_npm_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (` + bind(1) + `, ` + bind(2) + `, ` + bind(3) + `, 'fixture', ` + bind(4) + `, 'now')`
	if _, err := db.ExecContext(ctx, query, pkg, workspace, npmRepo, user); err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512([]byte("synthetic"))
	query = `INSERT INTO registry_npm_versions (npm_version_id, workspace_id, repository_id, package_id, version, version_identity, manifest, tarball_sha256, tarball_size, integrity, created_by, created_at) VALUES (` + bind(1) + `, ` + bind(2) + `, ` + bind(3) + `, ` + bind(4) + `, '1.0.0', '1.0.0', '{}', ` + bind(5) + `, 7, ` + bind(6) + `, ` + bind(7) + `, 'now')`
	if _, err := db.ExecContext(ctx, query, uuid.NewString(), workspace, npmRepo, pkg, strings.Repeat("b", 64), "sha512-"+base64.StdEncoding.EncodeToString(digest[:]), user); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := service.checkReservationQuota(ctx, tx, workspace, goRepo, 4); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("npm version did not count towards Go quota: %v", err)
	}
	if err := service.checkReservationQuota(ctx, tx, workspace, goRepo, 3); err != nil {
		t.Fatalf("remaining Go quota rejected: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, user, workspace, npmRepo, user, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	npmToken, err := repos.IssueNPMWriteToken(ctx, user, workspace, npmRepo, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	npmService, err := npm.NewReservationService(db, repos, driver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := npmService.Reserve(ctx, npmToken.Bearer, workspace, npmRepo, npm.ReservationRequest{Name: "reserved", Version: "1.0.0", TarballSHA256: strings.Repeat("c", 64), TarballSize: 2, MetadataSHA256: strings.Repeat("d", 64)}); err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := service.checkReservationQuota(ctx, tx, workspace, goRepo, 2); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("npm reservation did not count towards Go quota: %v", err)
	}
	if err := service.checkReservationQuota(ctx, tx, workspace, goRepo, 1); err != nil {
		t.Fatalf("remaining Go quota rejected after npm reservation: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_workspaces SET logical_quota_bytes = 24 WHERE workspace_id = `+bind(1), workspace); err != nil {
		t.Fatal(err)
	}
	pubRepo, pubPackage := uuid.NewString(), uuid.NewString()
	query = `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + bind(1) + `, ` + bind(2) + `, 'pub', 'Pub', ` + bind(3) + `, 'now', 'now', 'pub')`
	if _, err := db.ExecContext(ctx, query, pubRepo, workspace, user); err != nil {
		t.Fatal(err)
	}
	query = `INSERT INTO registry_pub_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (` + bind(1) + `, ` + bind(2) + `, ` + bind(3) + `, 'fixture', ` + bind(4) + `, 'now')`
	if _, err := db.ExecContext(ctx, query, pubPackage, workspace, pubRepo, user); err != nil {
		t.Fatal(err)
	}
	query = `INSERT INTO registry_pub_versions (pub_version_id, workspace_id, repository_id, package_id, version, version_identity, manifest, tarball_sha256, tarball_size, created_by, created_at) VALUES (` + bind(1) + `, ` + bind(2) + `, ` + bind(3) + `, ` + bind(4) + `, '1.0.0', '1.0.0', 'fixture', ` + bind(5) + `, 7, ` + bind(6) + `, 'now')`
	if _, err := db.ExecContext(ctx, query, uuid.NewString(), workspace, pubRepo, pubPackage, strings.Repeat("a", 64), user); err != nil {
		t.Fatal(err)
	}
	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := service.checkReservationQuota(ctx, tx, workspace, goRepo, 2); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Pub version did not count towards Go quota: %v", err)
	}
	if err := service.checkReservationQuota(ctx, tx, workspace, goRepo, 1); err != nil {
		t.Fatalf("remaining Go quota rejected after Pub version: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, user, workspace, pubRepo, user, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	pubToken, err := repos.IssuePubWriteToken(ctx, user, workspace, pubRepo, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pubService, err := pub.NewReservationService(db, repos, driver)
	if err != nil {
		t.Fatal(err)
	}
	pubReservation, err := pubService.Reserve(ctx, pubToken.Bearer, workspace, pubRepo, pub.ReservationRequest{Name: "reserved", Version: "1.0.0", TarballSHA256: strings.Repeat("f", 64), TarballSize: 1, MetadataSHA256: strings.Repeat("d", 64)})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"reserved", "uploading", "uploaded"} {
		if state == "uploading" {
			query = `UPDATE registry_pub_reservations SET status = 'uploading', upload_claim_id = ` + bind(1) + ` WHERE reservation_id = ` + bind(2)
			if _, err := db.ExecContext(ctx, query, uuid.NewString(), pubReservation.ID); err != nil {
				t.Fatal(err)
			}
		} else if state == "uploaded" {
			query = `UPDATE registry_pub_reservations SET status = 'uploaded', upload_claim_id = NULL, object_verified = 1, manifest = 'fixture' WHERE reservation_id = ` + bind(1)
			if _, err := db.ExecContext(ctx, query, pubReservation.ID); err != nil {
				t.Fatal(err)
			}
		}
		tx, err = db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.checkReservationQuota(ctx, tx, workspace, goRepo, 1); !errors.Is(err, ErrQuotaExceeded) {
			_ = tx.Rollback()
			t.Fatalf("Pub %s did not count towards Go quota: %v", state, err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
	}
}
