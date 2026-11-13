package repositories

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/workspaces"
)

func TestRepositoryAuthorizationNamesAndVisibilityPolicy(t *testing.T) {
	ctx, db, driver := openSQLite(t)
	repositoryService, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	ownerID := seedUser(t, ctx, db, driver, true)
	instanceAdminID := seedUser(t, ctx, db, driver, true)
	adminID := seedUser(t, ctx, db, driver, false)
	memberID := seedUser(t, ctx, db, driver, false)
	workspaceOwnerID := seedUser(t, ctx, db, driver, false)
	outsiderID := seedUser(t, ctx, db, driver, false)
	workspace, err := workspaceService.CreateWorkspace(ctx, ownerID, "repo-workspace", "Repository Workspace")
	if err != nil {
		t.Fatal(err)
	}
	otherWorkspace, err := workspaceService.CreateWorkspace(ctx, ownerID, "other-workspace", "Other Workspace")
	if err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, ownerID, workspace.ID, adminID, workspaces.RoleAdministrator); err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, ownerID, workspace.ID, memberID, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, ownerID, workspace.ID, workspaceOwnerID, workspaces.RoleOwner); err != nil {
		t.Fatal(err)
	}

	policy, err := repositoryService.VisibilityPolicy(ctx, ownerID)
	if err != nil || policy != PolicyPrivateOnly {
		t.Fatalf("unexpected initial visibility policy: policy=%q err=%v", policy, err)
	}
	if _, err := repositoryService.VisibilityPolicy(ctx, memberID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-administrator read the administrative visibility policy: %v", err)
	}
	if policy, err := repositoryService.VisibilityPolicy(ctx, instanceAdminID); err != nil || policy != PolicyPrivateOnly {
		t.Fatalf("separate installation administrator could not read the policy: policy=%q err=%v", policy, err)
	}
	if _, err := repositoryService.Create(ctx, memberID, workspace.ID, "member-repo", "Member Repo"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ordinary member created a repository: %v", err)
	}

	created, err := repositoryService.Create(ctx, adminID, workspace.ID, "release-tools", "  Release Tools  ")
	if err != nil {
		t.Fatal(err)
	}
	if created.Visibility != VisibilityPrivate || created.DisplayName != "Release Tools" || created.Status != "active" {
		t.Fatalf("new repository did not use private normalized defaults: %+v", created)
	}
	parsedID, err := uuid.Parse(created.ID)
	if err != nil || parsedID.Version() != 7 {
		t.Fatalf("repository identity is not UUIDv7: %q (%v)", created.ID, err)
	}
	if _, err := repositoryService.Create(ctx, ownerID, workspace.ID, "release-tools", "Duplicate"); !errors.Is(err, ErrSlugConflict) {
		t.Fatalf("duplicate repository slug was accepted: %v", err)
	}
	if _, err := repositoryService.Create(ctx, ownerID, workspace.ID, "Bad/Slug", "Invalid"); !errors.Is(err, ErrInvalidSlug) {
		t.Fatalf("invalid repository slug was accepted: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET slug = ? WHERE repository_id = ?`,
		"renamed", created.ID); err == nil {
		t.Fatal("database allowed a repository slug change")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET workspace_id = ? WHERE repository_id = ?`,
		otherWorkspace.ID, created.ID); err == nil {
		t.Fatal("database allowed a repository to move between workspaces")
	}

	if _, _, err := repositoryService.ListForWorkspace(ctx, memberID, workspace.ID, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("workspace membership implied repository access: %v", err)
	}
	if _, _, err := repositoryService.ListForWorkspace(ctx, outsiderID, workspace.ID, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("user without workspace membership listed repositories: %v", err)
	}
	if _, _, err := repositoryService.ListForWorkspace(ctx, instanceAdminID, workspace.ID, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("installation administrator without workspace membership listed repositories: %v", err)
	}
	listed, hasMore, err := repositoryService.ListForWorkspace(ctx, adminID, workspace.ID, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if hasMore || len(listed) != 1 || listed[0].ID != created.ID || listed[0].Visibility != VisibilityPrivate {
		t.Fatalf("workspace administrator received an unexpected repository listing: %+v has_more=%t",
			listed, hasMore)
	}
	if _, _, err := repositoryService.ListForWorkspace(ctx, workspaceOwnerID, workspace.ID, "", 10); err != nil {
		t.Fatalf("ordinary workspace owner could not list repository metadata: %v", err)
	}

	if err := repositoryService.SetVisibility(ctx, adminID, workspace.ID,
		created.ID, VisibilityUnlisted, true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("workspace administrator changed repository visibility: %v", err)
	}
	if err := repositoryService.SetVisibility(ctx, instanceAdminID, workspace.ID,
		created.ID, VisibilityUnlisted, true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("installation administrator without workspace ownership changed repository visibility: %v", err)
	}
	if err := repositoryService.SetVisibility(ctx, ownerID, workspace.ID,
		created.ID, VisibilityUnlisted, false); !errors.Is(err, ErrVisibilityNotAllowed) {
		t.Fatalf("unlisted visibility was enabled under private-only policy without confirmation: %v", err)
	}
	if err := repositoryService.SetVisibility(ctx, ownerID, workspace.ID,
		created.ID, VisibilityUnlisted, true); !errors.Is(err, ErrVisibilityNotAllowed) {
		t.Fatalf("unlisted visibility was enabled under private-only policy: %v", err)
	}
	if err := repositoryService.SetVisibilityPolicy(ctx, memberID, PolicyAll); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-administrator changed the installation policy: %v", err)
	}
	if err := repositoryService.SetVisibilityPolicy(ctx, workspaceOwnerID, PolicyAll); !errors.Is(err, ErrForbidden) {
		t.Fatalf("workspace owner changed the installation-wide visibility policy: %v", err)
	}
	if err := repositoryService.SetVisibilityPolicy(ctx, instanceAdminID, PolicyPrivateAndUnlisted); err != nil {
		t.Fatal(err)
	}
	if err := repositoryService.SetVisibility(ctx, workspaceOwnerID, workspace.ID,
		created.ID, VisibilityUnlisted, false); !errors.Is(err, ErrPublicConfirmation) {
		t.Fatalf("public transition without confirmation was accepted after enabling its mode: %v", err)
	}
	if err := repositoryService.SetVisibility(ctx, workspaceOwnerID, workspace.ID,
		created.ID, VisibilityUnlisted, true); err != nil {
		t.Fatalf("owner could not enable allowed unlisted visibility: %v", err)
	}
	if err := repositoryService.SetVisibilityPolicy(ctx, instanceAdminID, PolicyPrivateOnly); err != nil {
		t.Fatal(err)
	}
	var persistedVisibility string
	if err := db.QueryRowContext(ctx,
		"SELECT visibility FROM registry_repositories WHERE repository_id = ?", created.ID).Scan(&persistedVisibility); err != nil {
		t.Fatal(err)
	}
	if persistedVisibility != string(VisibilityUnlisted) {
		t.Fatalf("restricting available modes converted an existing repository: %q", persistedVisibility)
	}
	if err := repositoryService.SetVisibility(ctx, workspaceOwnerID, workspace.ID,
		created.ID, VisibilityListed, true); !errors.Is(err, ErrVisibilityNotAllowed) {
		t.Fatalf("listed visibility was allowed after the policy was restricted: %v", err)
	}
	if err := repositoryService.SetVisibility(ctx, workspaceOwnerID, workspace.ID,
		created.ID, VisibilityPrivate, false); err != nil {
		t.Fatalf("owner could not make a repository private: %v", err)
	}
	if err := repositoryService.SetVisibilityPolicy(ctx, instanceAdminID, PolicyAll); err != nil {
		t.Fatal(err)
	}
	if err := repositoryService.SetVisibility(ctx, workspaceOwnerID, workspace.ID,
		created.ID, VisibilityListed, true); err != nil {
		t.Fatalf("owner could not enable listed visibility after explicit confirmation: %v", err)
	}
	if err := repositoryService.UpdateDisplayName(ctx, adminID, workspace.ID,
		created.ID, "Release Infrastructure"); err != nil {
		t.Fatalf("workspace administrator could not update repository display name: %v", err)
	}
	if err := repositoryService.UpdateDisplayName(ctx, memberID, workspace.ID,
		created.ID, "Unauthorized Rename"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ordinary member renamed a repository: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT display_name, slug, visibility FROM registry_repositories
		WHERE repository_id = ?`, created.ID).Scan(&created.DisplayName, &created.Slug, &persistedVisibility); err != nil {
		t.Fatal(err)
	}
	if created.DisplayName != "Release Infrastructure" || created.Slug != "release-tools" ||
		persistedVisibility != string(VisibilityListed) {
		t.Fatalf("repository update changed the wrong fields: name=%q slug=%q visibility=%q",
			created.DisplayName, created.Slug, persistedVisibility)
	}
	var auditCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events
		WHERE target_type IN ('repository', 'installation')`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 8 {
		t.Fatalf("repository and policy writes were not audited exactly once: count=%d", auditCount)
	}
}

func TestRepositoryGrantsAreExplicitScopedAndRevokedWithMembership(t *testing.T) {
	ctx, db, driver := openSQLite(t)
	repositoryService, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	ownerID := seedUser(t, ctx, db, driver, true)
	instanceAdminID := seedUser(t, ctx, db, driver, true)
	adminID := seedUser(t, ctx, db, driver, false)
	memberID := seedUser(t, ctx, db, driver, false)
	otherWorkspaceMemberID := seedUser(t, ctx, db, driver, false)
	workspace, err := workspaceService.CreateWorkspace(ctx, ownerID, "grant-workspace", "Grant Workspace")
	if err != nil {
		t.Fatal(err)
	}
	otherWorkspace, err := workspaceService.CreateWorkspace(ctx, ownerID, "grant-other", "Grant Other")
	if err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, ownerID, workspace.ID, adminID, workspaces.RoleAdministrator); err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, ownerID, workspace.ID, memberID, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, ownerID, otherWorkspace.ID,
		otherWorkspaceMemberID, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	repository, err := repositoryService.Create(ctx, ownerID, workspace.ID, "grant-target", "Grant Target")
	if err != nil {
		t.Fatal(err)
	}

	for _, principalID := range []string{ownerID, adminID, memberID} {
		for _, role := range []GrantRole{GrantReader, GrantPublisher} {
			allowed, err := repositoryService.HasRepositoryGrant(
				ctx, principalID, workspace.ID, repository.ID, role)
			if err != nil || allowed {
				t.Fatalf("principal received implicit repository grant: user=%q role=%q allowed=%t err=%v",
					principalID, role, allowed, err)
			}
		}
	}
	if allowed, err := repositoryService.HasRepositoryGrant(
		ctx, instanceAdminID, workspace.ID, repository.ID, GrantPublisher); !errors.Is(err, ErrForbidden) || allowed {
		t.Fatalf("installation administrator without workspace membership received grant access: allowed=%t err=%v", allowed, err)
	}
	if _, err := repositoryService.GrantRepositoryRole(
		ctx, adminID, workspace.ID, repository.ID, adminID, GrantReader); !errors.Is(err, ErrForbidden) {
		t.Fatalf("administrator granted a role to themself: %v", err)
	}
	if _, err := repositoryService.GrantRepositoryRole(
		ctx, adminID, workspace.ID, repository.ID, memberID, GrantMaintainer); !errors.Is(err, ErrForbidden) {
		t.Fatalf("administrator delegated a non-delegable role: %v", err)
	}
	if _, err := repositoryService.GrantRepositoryRole(
		ctx, adminID, workspace.ID, repository.ID, otherWorkspaceMemberID, GrantReader); !errors.Is(err, ErrMembershipUnavailable) {
		t.Fatalf("administrator granted access to a user outside the workspace: %v", err)
	}

	readerGrant, err := repositoryService.GrantRepositoryRole(
		ctx, adminID, workspace.ID, repository.ID, memberID, GrantReader)
	if err != nil {
		t.Fatal(err)
	}
	duplicateReaderGrant, err := repositoryService.GrantRepositoryRole(
		ctx, ownerID, workspace.ID, repository.ID, memberID, GrantReader)
	if err != nil {
		t.Fatal(err)
	}
	if duplicateReaderGrant.ID != readerGrant.ID || duplicateReaderGrant.GrantedBy != adminID {
		t.Fatalf("repeating an active grant replaced its history: first=%+v repeated=%+v", readerGrant, duplicateReaderGrant)
	}
	publisherGrant, err := repositoryService.GrantRepositoryRole(
		ctx, adminID, workspace.ID, repository.ID, memberID, GrantPublisher)
	if err != nil {
		t.Fatal(err)
	}
	maintainerGrant, err := repositoryService.GrantRepositoryRole(
		ctx, ownerID, workspace.ID, repository.ID, memberID, GrantMaintainer)
	if err != nil {
		t.Fatal(err)
	}
	if maintainerGrant.ID == "" || maintainerGrant.Role != GrantMaintainer {
		t.Fatalf("owner's maintainer grant was incomplete: %+v", maintainerGrant)
	}
	if _, err := repositoryService.GrantRepositoryRole(
		ctx, adminID, workspace.ID, repository.ID, memberID, GrantSecurity); !errors.Is(err, ErrForbidden) {
		t.Fatalf("administrator granted a security role: %v", err)
	}
	ownerPublisher, err := repositoryService.GrantRepositoryRole(
		ctx, ownerID, workspace.ID, repository.ID, ownerID, GrantPublisher)
	if err != nil {
		t.Fatalf("owner could not explicitly grant themself publisher: %v", err)
	}
	if ownerPublisher.GrantedBy != ownerID {
		t.Fatalf("owner self-grant was not attributed: %+v", ownerPublisher)
	}
	ownerSecurity, err := repositoryService.GrantRepositoryRole(
		ctx, ownerID, workspace.ID, repository.ID, ownerID, GrantSecurity)
	if err != nil {
		t.Fatalf("owner could not explicitly grant themself security: %v", err)
	}
	_ = ownerSecurity

	for _, role := range []GrantRole{GrantReader, GrantPublisher, GrantMaintainer} {
		allowed, err := repositoryService.HasRepositoryGrant(ctx, memberID, workspace.ID, repository.ID, role)
		if err != nil || !allowed {
			t.Fatalf("explicit repository grant was not effective: role=%q allowed=%t err=%v", role, allowed, err)
		}
	}
	if _, err := repositoryService.HasRepositoryGrant(
		ctx, otherWorkspaceMemberID, workspace.ID, repository.ID, GrantReader); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-workspace user queried effective repository access: %v", err)
	}
	allowed, err := repositoryService.HasRepositoryGrant(
		ctx, otherWorkspaceMemberID, otherWorkspace.ID, repository.ID, GrantReader)
	if err != nil || allowed {
		t.Fatalf("repository grant crossed the workspace boundary: allowed=%t err=%v", allowed, err)
	}
	if _, _, err := repositoryService.ListRepositoryGrants(
		ctx, memberID, workspace.ID, repository.ID, "", 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ordinary member listed the repository's grants: %v", err)
	}
	grants, hasMore, err := repositoryService.ListRepositoryGrants(
		ctx, adminID, workspace.ID, repository.ID, "", 3)
	if err != nil {
		t.Fatal(err)
	}
	if !hasMore || len(grants) != 3 {
		t.Fatalf("grant listing did not enforce keyset pagination: grants=%+v has_more=%t", grants, hasMore)
	}
	secondPage, hasMore, err := repositoryService.ListRepositoryGrants(
		ctx, ownerID, workspace.ID, repository.ID, grants[2].ID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if hasMore || len(secondPage) != 2 {
		t.Fatalf("grant listing returned an unexpected second page: grants=%+v has_more=%t", secondPage, hasMore)
	}

	if err := repositoryService.RevokeRepositoryRole(
		ctx, adminID, workspace.ID, repository.ID, memberID, GrantMaintainer); !errors.Is(err, ErrForbidden) {
		t.Fatalf("administrator revoked a non-delegable role: %v", err)
	}
	if err := repositoryService.RevokeRepositoryRole(
		ctx, adminID, workspace.ID, repository.ID, memberID, GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if err := repositoryService.RevokeRepositoryRole(
		ctx, ownerID, workspace.ID, repository.ID, memberID, GrantMaintainer); err != nil {
		t.Fatal(err)
	}
	if err := repositoryService.RevokeRepositoryRole(
		ctx, ownerID, workspace.ID, repository.ID, memberID, GrantMaintainer); err != nil {
		t.Fatalf("repeated grant revocation was not idempotent: %v", err)
	}
	for _, role := range []GrantRole{GrantPublisher, GrantMaintainer} {
		allowed, err := repositoryService.HasRepositoryGrant(ctx, memberID, workspace.ID, repository.ID, role)
		if err != nil || allowed {
			t.Fatalf("revoked grant remained effective: role=%q allowed=%t err=%v", role, allowed, err)
		}
	}

	if err := workspaceService.RemoveMembership(ctx, ownerID, workspace.ID, memberID); err != nil {
		t.Fatal(err)
	}
	if allowed, err := repositoryService.HasRepositoryGrant(
		ctx, memberID, workspace.ID, repository.ID, GrantReader); !errors.Is(err, ErrForbidden) || allowed {
		t.Fatalf("removed membership retained effective repository access: allowed=%t err=%v", allowed, err)
	}
	var membershipRevocations int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_repository_grants
		WHERE user_id = ? AND workspace_id = ? AND revoked_at IS NOT NULL
			AND revocation_reason = 'membership_inactive' AND revoked_by IS NULL`, memberID, workspace.ID).
		Scan(&membershipRevocations); err != nil {
		t.Fatal(err)
	}
	if membershipRevocations != 1 {
		t.Fatalf("membership removal did not revoke its remaining active grants: count=%d", membershipRevocations)
	}
	if err := workspaceService.SetMembershipRole(
		ctx, ownerID, workspace.ID, memberID, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	if allowed, err := repositoryService.HasRepositoryGrant(
		ctx, memberID, workspace.ID, repository.ID, GrantReader); err != nil || allowed {
		t.Fatalf("readmission restored a revoked grant: allowed=%t err=%v", allowed, err)
	}
	reissuedGrant, err := repositoryService.GrantRepositoryRole(
		ctx, ownerID, workspace.ID, repository.ID, memberID, GrantReader)
	if err != nil {
		t.Fatal(err)
	}
	if reissuedGrant.ID == readerGrant.ID {
		t.Fatalf("re-grant did not preserve the original grant history: old=%q new=%q", readerGrant.ID, reissuedGrant.ID)
	}
	if allowed, err := repositoryService.HasRepositoryGrant(
		ctx, memberID, workspace.ID, repository.ID, GrantReader); err != nil || !allowed {
		t.Fatalf("explicitly reissued grant was not effective: allowed=%t err=%v", allowed, err)
	}

	var manualRevocation string
	var manualRevoker string
	if err := db.QueryRowContext(ctx, `SELECT revocation_reason, revoked_by
		FROM registry_repository_grants WHERE grant_id = ?`, publisherGrant.ID).
		Scan(&manualRevocation, &manualRevoker); err != nil {
		t.Fatal(err)
	}
	if manualRevocation != "manual" || manualRevoker != adminID {
		t.Fatalf("manual grant revocation was not attributed: reason=%q actor=%q", manualRevocation, manualRevoker)
	}
	var grantCreatedEvents int
	var grantRevokedEvents int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events
		WHERE action = 'repository.grant.created' AND target_type = 'repository_grant'`).
		Scan(&grantCreatedEvents); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events
		WHERE action = 'repository.grant.revoked' AND target_type = 'repository_grant'`).
		Scan(&grantRevokedEvents); err != nil {
		t.Fatal(err)
	}
	if grantCreatedEvents != 6 || grantRevokedEvents != 2 {
		t.Fatalf("grant lifecycle was not audited exactly once: created=%d revoked=%d",
			grantCreatedEvents, grantRevokedEvents)
	}
	var membershipAuditEvents int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events
		WHERE action = 'workspace.membership.removed' AND target_id = ?`, workspace.ID+"/"+memberID).
		Scan(&membershipAuditEvents); err != nil {
		t.Fatal(err)
	}
	if membershipAuditEvents != 1 {
		t.Fatalf("membership-triggered grant revocation lacked its membership audit event: %d", membershipAuditEvents)
	}
}

func openSQLite(t *testing.T) (context.Context, *sql.DB, config.DatabaseDriver) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	dataDir := filepath.Join(t.TempDir(), "registry-data")
	cfg := config.Config{
		DataDir:              dataDir,
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          filepath.Join(dataDir, "registry.sqlite"),
		DatabaseMaxOpenConns: 4,
	}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close SQLite database: %v", err)
		}
	})
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	return ctx, db, cfg.DatabaseDriver
}

func seedUser(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver, administrator bool) string {
	t.Helper()
	userID := newUUID(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	query := `INSERT INTO registry_users
		(user_id, display_name, email, email_verified, status, created_at, updated_at)
		VALUES (` + bind(driver, 1) + `, 'Repository Test User', NULL, FALSE, 'active', ` + bind(driver, 2) + `, ` + bind(driver, 3) + `)`
	if _, err := db.ExecContext(ctx, query, userID, now, now); err != nil {
		t.Fatal(err)
	}
	if administrator {
		seedInstanceAdmin(t, ctx, db, driver, userID)
	}
	return userID
}

func seedInstanceAdmin(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver, userID string) {
	t.Helper()
	query := `INSERT INTO registry_instance_admins (user_id, granted_by, granted_at)
		VALUES (` + bind(driver, 1) + `, NULL, ` + bind(driver, 2) + `)`
	if _, err := db.ExecContext(ctx, query, userID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func newUUID(t *testing.T) string {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return value.String()
}
