//go:build integration

package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/testinfra"
	"private-registry/internal/workspaces"
)

func TestPostgresRepositoryIdentityAuthorizationAndVisibility(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	fixture, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Errorf("stop owned PostgreSQL fixture: %v", err)
		}
	})
	cfg := config.Config{
		DatabaseDriver:       config.Postgres,
		DatabaseDSN:          fixture.DSN(),
		DatabaseMaxOpenConns: 4,
	}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close PostgreSQL database: %v", err)
		}
	})
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, config.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	repositoryService, err := New(db, config.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	ownerID := seedUser(t, ctx, db, config.Postgres, true)
	instanceAdminID := seedUser(t, ctx, db, config.Postgres, true)
	workspaceAdminID := seedUser(t, ctx, db, config.Postgres, false)
	memberID := seedUser(t, ctx, db, config.Postgres, false)
	workspaceOwnerID := seedUser(t, ctx, db, config.Postgres, false)
	workspace, err := workspaceService.CreateWorkspace(ctx, ownerID, "postgres-repositories", "Postgres Repositories")
	if err != nil {
		t.Fatal(err)
	}
	otherWorkspace, err := workspaceService.CreateWorkspace(ctx, ownerID, "postgres-other", "Postgres Other")
	if err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, ownerID, workspace.ID, memberID, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, ownerID, workspace.ID, workspaceAdminID, workspaces.RoleAdministrator); err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, ownerID, workspace.ID, workspaceOwnerID, workspaces.RoleOwner); err != nil {
		t.Fatal(err)
	}
	repository, err := repositoryService.Create(ctx, ownerID, workspace.ID, "private-artifacts", "Private Artifacts")
	if err != nil {
		t.Fatal(err)
	}
	if repository.Visibility != VisibilityPrivate {
		t.Fatalf("PostgreSQL repository was not private by default: %q", repository.Visibility)
	}
	exerciseQuotaAdministration(t, ctx, db, repositoryService, config.Postgres, instanceAdminID, memberID, workspace.ID, repository.ID)
	exerciseRecoveryJobAdministration(t, ctx, db, repositoryService, config.Postgres, instanceAdminID, memberID)
	exerciseDeadJobAdministration(t, ctx, db, repositoryService, config.Postgres, instanceAdminID, memberID)
	if _, _, err := repositoryService.ListForWorkspace(ctx, memberID, workspace.ID, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("PostgreSQL membership implied repository read access: %v", err)
	}
	if _, _, err := repositoryService.ListForWorkspace(ctx, instanceAdminID, workspace.ID, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("PostgreSQL installation administrator without workspace membership listed repositories: %v", err)
	}
	if allowed, err := repositoryService.HasRepositoryGrant(ctx, memberID, workspace.ID, repository.ID, GrantReader); err != nil || allowed {
		t.Fatalf("PostgreSQL membership implied a repository grant: allowed=%t err=%v", allowed, err)
	}
	if _, err := repositoryService.GrantRepositoryRole(
		ctx, workspaceAdminID, workspace.ID, repository.ID, memberID, GrantMaintainer); !errors.Is(err, ErrForbidden) {
		t.Fatalf("PostgreSQL workspace administrator delegated a non-delegable role: %v", err)
	}
	if _, err := repositoryService.GrantRepositoryRole(
		ctx, workspaceAdminID, workspace.ID, repository.ID, workspaceAdminID, GrantReader); !errors.Is(err, ErrForbidden) {
		t.Fatalf("PostgreSQL workspace administrator granted themself a role: %v", err)
	}
	readerGrant, err := repositoryService.GrantRepositoryRole(
		ctx, workspaceAdminID, workspace.ID, repository.ID, memberID, GrantReader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repositoryService.GrantRepositoryRole(
		ctx, workspaceAdminID, workspace.ID, repository.ID, memberID, GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := repositoryService.GrantRepositoryRole(
		ctx, ownerID, workspace.ID, repository.ID, memberID, GrantSecurity); err != nil {
		t.Fatal(err)
	}
	if allowed, err := repositoryService.HasRepositoryGrant(ctx, memberID, workspace.ID, repository.ID, GrantReader); err != nil || !allowed {
		t.Fatalf("PostgreSQL explicit reader grant was not effective: allowed=%t err=%v", allowed, err)
	}
	if allowed, err := repositoryService.HasRepositoryGrant(ctx, ownerID, workspace.ID, repository.ID, GrantPublisher); err != nil || allowed {
		t.Fatalf("PostgreSQL owner received implicit publisher access: allowed=%t err=%v", allowed, err)
	}
	if err := workspaceService.RemoveMembership(ctx, ownerID, workspace.ID, memberID); err != nil {
		t.Fatal(err)
	}
	var revokedCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_repository_grants
		WHERE workspace_id = $1 AND user_id = $2 AND revoked_at IS NOT NULL
			AND revocation_reason = 'membership_inactive' AND revoked_by IS NULL`, workspace.ID, memberID).
		Scan(&revokedCount); err != nil {
		t.Fatal(err)
	}
	if revokedCount != 3 {
		t.Fatalf("PostgreSQL membership removal did not revoke all active grants: %d", revokedCount)
	}
	if err := workspaceService.SetMembershipRole(ctx, ownerID, workspace.ID, memberID, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	if allowed, err := repositoryService.HasRepositoryGrant(ctx, memberID, workspace.ID, repository.ID, GrantReader); err != nil || allowed {
		t.Fatalf("PostgreSQL readmission restored a revoked grant: allowed=%t err=%v", allowed, err)
	}
	reissuedGrant, err := repositoryService.GrantRepositoryRole(
		ctx, ownerID, workspace.ID, repository.ID, memberID, GrantReader)
	if err != nil {
		t.Fatal(err)
	}
	if reissuedGrant.ID == readerGrant.ID {
		t.Fatalf("PostgreSQL re-grant reused the old grant ID: %q", reissuedGrant.ID)
	}
	var grantAuditCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events
		WHERE action = 'repository.grant.created' AND target_type = 'repository_grant'`).
		Scan(&grantAuditCount); err != nil {
		t.Fatal(err)
	}
	if grantAuditCount != 4 {
		t.Fatalf("PostgreSQL grant creation did not emit one audit event per grant: %d", grantAuditCount)
	}
	var membershipAuditCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events
		WHERE action = 'workspace.membership.removed' AND target_id = $1`, workspace.ID+"/"+memberID).
		Scan(&membershipAuditCount); err != nil {
		t.Fatal(err)
	}
	if membershipAuditCount != 1 {
		t.Fatalf("PostgreSQL grant revocation lacked its membership audit event: %d", membershipAuditCount)
	}
	if err := repositoryService.SetVisibility(ctx, instanceAdminID, workspace.ID,
		repository.ID, VisibilityListed, true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("PostgreSQL installation administrator without workspace ownership changed visibility: %v", err)
	}
	if err := repositoryService.SetVisibilityPolicy(ctx, workspaceOwnerID, PolicyAll); !errors.Is(err, ErrForbidden) {
		t.Fatalf("PostgreSQL workspace owner changed the installation policy: %v", err)
	}
	if err := repositoryService.SetVisibilityPolicy(ctx, instanceAdminID, PolicyAll); err != nil {
		t.Fatal(err)
	}
	if err := repositoryService.SetVisibility(ctx, workspaceOwnerID, workspace.ID,
		repository.ID, VisibilityListed, true); err != nil {
		t.Fatalf("PostgreSQL owner could not set confirmed listed visibility: %v", err)
	}
	if err := repositoryService.SetVisibilityPolicy(ctx, instanceAdminID, PolicyPrivateOnly); err != nil {
		t.Fatal(err)
	}
	if err := repositoryService.SetVisibility(ctx, workspaceOwnerID, workspace.ID,
		repository.ID, VisibilityUnlisted, true); !errors.Is(err, ErrVisibilityNotAllowed) {
		t.Fatalf("PostgreSQL accepted a newly forbidden visibility: %v", err)
	}
	var visibility string
	if err := db.QueryRowContext(ctx,
		"SELECT visibility FROM registry_repositories WHERE repository_id = $1", repository.ID).Scan(&visibility); err != nil {
		t.Fatal(err)
	}
	if visibility != string(VisibilityListed) {
		t.Fatalf("restricting PostgreSQL policy converted an existing repository: %q", visibility)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET slug = $1 WHERE repository_id = $2`,
		"renamed", repository.ID); err == nil {
		t.Fatal("PostgreSQL allowed repository slug mutation")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET workspace_id = $1 WHERE repository_id = $2`,
		otherWorkspace.ID, repository.ID); err == nil {
		t.Fatal("PostgreSQL allowed repository workspace movement")
	}
	var auditCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events
		WHERE target_type IN ('repository', 'installation') AND actor_type = 'user' AND action <> 'logical_quota.changed'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 4 {
		t.Fatalf("PostgreSQL repository and policy mutations were not audited: %d", auditCount)
	}
	exerciseGoNamespacePolicy(t, ctx, db, config.Postgres)
	exercisePersonalReadTokens(t, ctx, db, config.Postgres)
	exerciseCargoWriteTokenLifecycle(t, ctx, db, config.Postgres)
	exerciseNPMWriteTokenLifecycle(t, ctx, db, config.Postgres)
	exercisePubWriteTokenLifecycle(t, ctx, db, config.Postgres)
}
