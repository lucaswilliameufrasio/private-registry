package workspaces

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
)

func TestWorkspaceCreationPolicyIsIndependentFromSignupAndAudited(t *testing.T) {
	ctx, db, cfg := openSQLite(t)
	driver := cfg.DatabaseDriver
	service, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	adminID := seedUser(t, ctx, db, driver, "active", "same@example.invalid")
	grantedUserID := seedUser(t, ctx, db, driver, "active", "same@example.invalid")
	otherUserID := seedUser(t, ctx, db, driver, "active", "other@example.invalid")
	suspendedUserID := seedUser(t, ctx, db, driver, "suspended", "suspended@example.invalid")
	seedInstanceAdmin(t, ctx, db, driver, adminID)

	if _, err := service.CreateWorkspace(ctx, otherUserID, "denied", "Denied"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin created a workspace under admin-only policy: %v", err)
	}
	if err := service.SetCreationPolicy(ctx, otherUserID, CreationAnyUser); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin changed workspace creation policy: %v", err)
	}

	if err := service.SetCreationPolicy(ctx, adminID, CreationAuthorizedUsers); err != nil {
		t.Fatal(err)
	}
	if err := service.GrantWorkspaceCreation(ctx, adminID, grantedUserID); err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateWorkspace(ctx, grantedUserID, "build-tools", "  Build Tools  ")
	if err != nil {
		t.Fatal(err)
	}
	if created.Slug != "build-tools" || created.DisplayName != "Build Tools" || created.Status != "active" {
		t.Fatalf("unexpected workspace: %+v", created)
	}
	parsedID, err := uuid.Parse(created.ID)
	if err != nil || parsedID.Version() != 7 {
		t.Fatalf("workspace ID is not UUIDv7: %q (%v)", created.ID, err)
	}
	var membershipRole string
	if err := db.QueryRowContext(ctx,
		"SELECT role FROM registry_workspace_memberships WHERE workspace_id = ? AND user_id = ?",
		created.ID, grantedUserID).Scan(&membershipRole); err != nil {
		t.Fatal(err)
	}
	if membershipRole != "owner" {
		t.Fatalf("workspace creator was not made owner: %q", membershipRole)
	}
	var signupPolicy, workspacePolicy string
	if err := db.QueryRowContext(ctx,
		"SELECT signup_policy, workspace_creation_policy FROM registry_installation WHERE singleton_id = 1").Scan(&signupPolicy, &workspacePolicy); err != nil {
		t.Fatal(err)
	}
	if signupPolicy != "closed" || workspacePolicy != string(CreationAuthorizedUsers) {
		t.Fatalf("signup and workspace creation policies were not independent: signup=%q workspace=%q", signupPolicy, workspacePolicy)
	}

	if _, err := service.CreateWorkspace(ctx, otherUserID, "not-allowed-yet", "Not Allowed"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ungranted user created a workspace: %v", err)
	}
	if err := service.RevokeWorkspaceCreation(ctx, adminID, grantedUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateWorkspace(ctx, grantedUserID, "revoked", "Revoked"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked user created a workspace: %v", err)
	}

	if err := service.SetCreationPolicy(ctx, adminID, CreationAnyUser); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateWorkspace(ctx, otherUserID, "open-workspace", "Open Workspace"); err != nil {
		t.Fatalf("active user could not create a workspace when policy is any_user: %v", err)
	}
	if _, err := service.CreateWorkspace(ctx, suspendedUserID, "suspended-workspace", "Suspended"); !errors.Is(err, ErrUserUnavailable) {
		t.Fatalf("suspended user created a workspace: %v", err)
	}

	var auditCount int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM registry_audit_events").Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 6 {
		t.Fatalf("unexpected successful tenancy audit count: %d", auditCount)
	}
}

func TestWorkspaceSlugIsValidatedUniqueAndImmutable(t *testing.T) {
	ctx, db, cfg := openSQLite(t)
	driver := cfg.DatabaseDriver
	service, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	userID := seedUser(t, ctx, db, driver, "active", "slug@example.invalid")
	seedInstanceAdmin(t, ctx, db, driver, userID)

	if _, err := service.CreateWorkspace(ctx, userID, "Uppercase", "Invalid"); !errors.Is(err, ErrInvalidSlug) {
		t.Fatalf("non-canonical slug was accepted: %v", err)
	}
	if _, err := service.CreateWorkspace(ctx, userID, "valid-slug", "\n\t"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("empty display name was accepted: %v", err)
	}
	workspace, err := service.CreateWorkspace(ctx, userID, "valid-slug", "Valid Workspace")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateWorkspace(ctx, userID, "valid-slug", "Duplicate"); !errors.Is(err, ErrSlugConflict) {
		t.Fatalf("duplicate workspace slug was accepted: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE registry_workspaces SET slug = ? WHERE workspace_id = ?", "renamed", workspace.ID); err == nil {
		t.Fatal("database allowed a workspace slug change")
	}
}

func TestListForUserScopesActiveMembershipsAndPaginatesByWorkspaceID(t *testing.T) {
	ctx, db, cfg := openSQLite(t)
	service, err := New(db, cfg.DatabaseDriver)
	if err != nil {
		t.Fatal(err)
	}
	adminID := seedUser(t, ctx, db, cfg.DatabaseDriver, "active", "list-admin@example.invalid")
	memberID := seedUser(t, ctx, db, cfg.DatabaseDriver, "active", "list-member@example.invalid")
	outsiderID := seedUser(t, ctx, db, cfg.DatabaseDriver, "active", "list-outsider@example.invalid")
	seedInstanceAdmin(t, ctx, db, cfg.DatabaseDriver, adminID)

	firstWorkspace, err := service.CreateWorkspace(ctx, adminID, "list-first", "First")
	if err != nil {
		t.Fatal(err)
	}
	secondWorkspace, err := service.CreateWorkspace(ctx, adminID, "list-second", "Second")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspace_memberships
		(workspace_id, user_id, role, status, created_by, created_at, updated_at)
		VALUES (?, ?, 'member', 'active', ?, ?, ?)`, firstWorkspace.ID, memberID, adminID,
		firstWorkspace.CreatedAt.Format(time.RFC3339Nano), firstWorkspace.CreatedAt.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspace_memberships
		(workspace_id, user_id, role, status, created_by, created_at, updated_at)
		VALUES (?, ?, 'member', 'removed', ?, ?, ?)`, secondWorkspace.ID, memberID, adminID,
		secondWorkspace.CreatedAt.Format(time.RFC3339Nano), secondWorkspace.CreatedAt.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}

	firstPage, hasMore, err := service.ListForUser(ctx, adminID, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPage) != 1 || !hasMore {
		t.Fatalf("workspace pagination did not report the next page: count=%d has_more=%t", len(firstPage), hasMore)
	}
	secondPage, hasMore, err := service.ListForUser(ctx, adminID, firstPage[0].Workspace.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(secondPage) != 1 || hasMore {
		t.Fatalf("workspace pagination returned an unexpected last page: count=%d has_more=%t", len(secondPage), hasMore)
	}
	seen := map[string]bool{firstPage[0].Workspace.ID: true, secondPage[0].Workspace.ID: true}
	if !seen[firstWorkspace.ID] || !seen[secondWorkspace.ID] {
		t.Fatalf("admin pagination omitted or duplicated a workspace: %+v", seen)
	}

	memberWorkspaces, hasMore, err := service.ListForUser(ctx, memberID, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if hasMore || len(memberWorkspaces) != 1 || memberWorkspaces[0].Workspace.ID != firstWorkspace.ID ||
		memberWorkspaces[0].Role != "member" {
		t.Fatalf("membership listing leaked or omitted workspaces: %+v has_more=%t", memberWorkspaces, hasMore)
	}
	outsiderWorkspaces, hasMore, err := service.ListForUser(ctx, outsiderID, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if hasMore || len(outsiderWorkspaces) != 0 {
		t.Fatalf("user without memberships saw workspaces: %+v has_more=%t", outsiderWorkspaces, hasMore)
	}
	if _, _, err := service.ListForUser(ctx, adminID, "not-a-uuid", 10); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("malformed workspace cursor was accepted: %v", err)
	}
	if _, _, err := service.ListForUser(ctx, adminID, "", 101); !errors.Is(err, ErrInvalidPageSize) {
		t.Fatalf("oversized workspace page was accepted: %v", err)
	}
}

func TestMembershipManagementEnforcesDelegationAndLastOwner(t *testing.T) {
	ctx, db, cfg := openSQLite(t)
	driver := cfg.DatabaseDriver
	service, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	ownerID := seedUser(t, ctx, db, driver, "active", "membership-owner@example.invalid")
	adminID := seedUser(t, ctx, db, driver, "active", "membership-admin@example.invalid")
	memberID := seedUser(t, ctx, db, driver, "active", "membership-member@example.invalid")
	secondMemberID := seedUser(t, ctx, db, driver, "active", "membership-second@example.invalid")
	seedInstanceAdmin(t, ctx, db, driver, ownerID)

	workspace, err := service.CreateWorkspace(ctx, ownerID, "membership", "Membership")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetMembershipRole(ctx, ownerID, workspace.ID, adminID, RoleAdministrator); err != nil {
		t.Fatal(err)
	}
	if err := service.SetMembershipRole(ctx, ownerID, workspace.ID, memberID, RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := service.SetMembershipRole(ctx, adminID, workspace.ID, secondMemberID, RoleMember); err != nil {
		t.Fatalf("workspace administrator could not delegate a member role: %v", err)
	}

	if err := service.SetMembershipRole(ctx, adminID, workspace.ID, adminID, RoleOwner); !errors.Is(err, ErrSelfElevation) {
		t.Fatalf("workspace administrator elevated their own role: %v", err)
	}
	if err := service.SetMembershipRole(ctx, adminID, workspace.ID, memberID, RoleAdministrator); !errors.Is(err, ErrForbidden) {
		t.Fatalf("workspace administrator granted a non-delegable role: %v", err)
	}
	if err := service.RemoveMembership(ctx, adminID, workspace.ID, ownerID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("workspace administrator removed an owner: %v", err)
	}
	if err := service.RemoveMembership(ctx, memberID, workspace.ID, secondMemberID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ordinary member managed another membership: %v", err)
	}
	if err := service.SetMembershipRole(ctx, memberID, workspace.ID, secondMemberID, RoleMember); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ordinary member granted a membership role: %v", err)
	}

	if err := service.SetMembershipRole(ctx, ownerID, workspace.ID, ownerID, RoleMember); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("last owner demoted themselves: %v", err)
	}
	if err := service.RemoveMembership(ctx, ownerID, workspace.ID, ownerID); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("last owner removed themselves: %v", err)
	}

	if err := service.SetMembershipRole(ctx, ownerID, workspace.ID, adminID, RoleOwner); err != nil {
		t.Fatalf("owner could not explicitly grant a second owner: %v", err)
	}
	if err := service.RemoveMembership(ctx, ownerID, workspace.ID, ownerID); err != nil {
		t.Fatalf("owner could not leave after another owner was active: %v", err)
	}
	if err := service.RemoveMembership(ctx, adminID, workspace.ID, adminID); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("remaining owner left without transferring ownership: %v", err)
	}
	if err := service.RemoveMembership(ctx, adminID, workspace.ID, memberID); err != nil {
		t.Fatalf("workspace administrator could not remove an ordinary member: %v", err)
	}
	if err := service.SetMembershipRole(ctx, ownerID, workspace.ID, secondMemberID, RoleMember); !errors.Is(err, ErrForbidden) {
		t.Fatalf("removed owner continued managing the workspace: %v", err)
	}

	var ownerRole, ownerStatus, memberStatus string
	if err := db.QueryRowContext(ctx, `SELECT role, status FROM registry_workspace_memberships
		WHERE workspace_id = ? AND user_id = ?`, workspace.ID, adminID).Scan(&ownerRole, &ownerStatus); err != nil {
		t.Fatal(err)
	}
	if ownerRole != RoleOwner || ownerStatus != "active" {
		t.Fatalf("second owner state was not persisted: role=%q status=%q", ownerRole, ownerStatus)
	}
	if err := db.QueryRowContext(ctx, `SELECT status FROM registry_workspace_memberships
		WHERE workspace_id = ? AND user_id = ?`, workspace.ID, memberID).Scan(&memberStatus); err != nil {
		t.Fatal(err)
	}
	if memberStatus != "removed" {
		t.Fatalf("member removal was not persisted: %q", memberStatus)
	}

	raceWorkspace, err := service.CreateWorkspace(ctx, ownerID, "membership-owner-race", "Membership Owner Race")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetMembershipRole(ctx, ownerID, raceWorkspace.ID, adminID, RoleOwner); err != nil {
		t.Fatal(err)
	}
	type removalResult struct {
		userID string
		err    error
	}
	startRemovals := make(chan struct{})
	removalResults := make(chan removalResult, 2)
	for _, userID := range []string{ownerID, adminID} {
		go func(userID string) {
			<-startRemovals
			removalResults <- removalResult{
				userID: userID,
				err:    service.RemoveMembership(ctx, userID, raceWorkspace.ID, userID),
			}
		}(userID)
	}
	close(startRemovals)
	successfulRemovals := 0
	lastOwnerRejections := 0
	for range 2 {
		result := <-removalResults
		if result.err == nil {
			successfulRemovals++
			continue
		}
		if errors.Is(result.err, ErrLastOwner) {
			lastOwnerRejections++
			continue
		}
		t.Fatalf("concurrent owner removal for %s failed unexpectedly: %v", result.userID, result.err)
	}
	if successfulRemovals != 1 || lastOwnerRejections != 1 {
		t.Fatalf("concurrent owner removal violated the invariant: succeeded=%d rejected=%d",
			successfulRemovals, lastOwnerRejections)
	}

	var membershipAuditCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events
		WHERE target_type = 'workspace_membership'`).Scan(&membershipAuditCount); err != nil {
		t.Fatal(err)
	}
	if membershipAuditCount != 8 {
		t.Fatalf("membership changes were not audited exactly once: count=%d", membershipAuditCount)
	}
}

func TestWorkspaceCreationSerializesDuplicateSlugAcrossConnections(t *testing.T) {
	ctx, firstDB, cfg := openSQLite(t)
	driver := cfg.DatabaseDriver
	secondDB, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := secondDB.Close(); err != nil {
			t.Errorf("close second SQLite connection: %v", err)
		}
	})
	firstService, err := New(firstDB, driver)
	if err != nil {
		t.Fatal(err)
	}
	secondService, err := New(secondDB, driver)
	if err != nil {
		t.Fatal(err)
	}
	firstUser := seedUser(t, ctx, firstDB, driver, "active", "first@example.invalid")
	secondUser := seedUser(t, ctx, firstDB, driver, "active", "second@example.invalid")
	seedInstanceAdmin(t, ctx, firstDB, driver, firstUser)
	if err := firstService.SetCreationPolicy(ctx, firstUser, CreationAnyUser); err != nil {
		t.Fatal(err)
	}

	type result struct {
		workspace Workspace
		err       error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var waitGroup sync.WaitGroup
	for _, testCase := range []struct {
		service *Service
		userID  string
	}{
		{service: firstService, userID: firstUser},
		{service: secondService, userID: secondUser},
	} {
		waitGroup.Add(1)
		go func(service *Service, userID string) {
			defer waitGroup.Done()
			<-start
			workspace, err := service.CreateWorkspace(ctx, userID, "one-winner", "One Winner")
			results <- result{workspace: workspace, err: err}
		}(testCase.service, testCase.userID)
	}
	close(start)
	waitGroup.Wait()
	close(results)

	successCount := 0
	conflictCount := 0
	for result := range results {
		if result.err == nil {
			if result.workspace.ID == "" {
				t.Fatal("successful workspace creation returned no workspace identity")
			}
			successCount++
			continue
		}
		if errors.Is(result.err, ErrSlugConflict) {
			conflictCount++
			continue
		}
		t.Fatalf("unexpected concurrent workspace result: %v", result.err)
	}
	if successCount != 1 || conflictCount != 1 {
		t.Fatalf("unexpected slug race outcome: succeeded=%d conflicted=%d", successCount, conflictCount)
	}
}

func TestExternalIdentityUniquenessUsesStableProviderSubjectNotEmail(t *testing.T) {
	ctx, db, cfg := openSQLite(t)
	driver := cfg.DatabaseDriver
	firstUser := seedUser(t, ctx, db, driver, "active", "duplicate@example.invalid")
	secondUser := seedUser(t, ctx, db, driver, "active", "duplicate@example.invalid")
	firstIdentityID := newUUID(t)
	query := `INSERT INTO registry_external_identities
		(external_identity_id, user_id, provider_id, issuer, subject, created_at)
		VALUES (?, ?, 'corp-idp', 'https://idp.example.invalid', 'stable-subject', ?)`
	if _, err := db.ExecContext(ctx, query, firstIdentityID, firstUser, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, query, newUUID(t), secondUser, time.Now().UTC().Format(time.RFC3339Nano)); err == nil {
		t.Fatal("same provider/issuer/subject was linked to a second user")
	}
	var usersWithEmail int
	if err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM registry_users WHERE email = ?", "duplicate@example.invalid").Scan(&usersWithEmail); err != nil {
		t.Fatal(err)
	}
	if usersWithEmail != 2 {
		t.Fatalf("email collisions were incorrectly rejected: %d users", usersWithEmail)
	}
}

func openSQLite(t *testing.T) (context.Context, *sql.DB, config.Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	cfg := sqliteConfig(t)
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
	return ctx, db, cfg
}

func sqliteConfig(t *testing.T) config.Config {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "registry-data")
	return config.Config{
		DataDir:              dataDir,
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          filepath.Join(dataDir, "registry.sqlite"),
		DatabaseMaxOpenConns: 4,
	}
}

func seedUser(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver, status, email string) string {
	t.Helper()
	userID := newUUID(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	query := `INSERT INTO registry_users
		(user_id, display_name, email, email_verified, status, created_at, updated_at)
		VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, ` + bind(driver, 3) + `, ` + bind(driver, 4) + `, ` + bind(driver, 5) + `, ` + bind(driver, 6) + `, ` + bind(driver, 7) + `)`
	if _, err := db.ExecContext(ctx, query, userID, "Test User", email, false, status, now, now); err != nil {
		t.Fatal(err)
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
