//go:build integration

package workspaces

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/testinfra"
)

func TestPostgresWorkspacePoliciesAuditAndSlugConstraint(t *testing.T) {
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
	service, err := New(db, config.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	adminID := seedPostgresUser(t, ctx, db, "active")
	creatorID := seedPostgresUser(t, ctx, db, "active")
	secondCreatorID := seedPostgresUser(t, ctx, db, "active")
	seedPostgresAdmin(t, ctx, db, adminID)

	if _, err := service.CreateWorkspace(ctx, creatorID, "blocked", "Blocked"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("PostgreSQL allowed workspace creation under admin-only policy: %v", err)
	}
	if err := service.SetCreationPolicy(ctx, adminID, CreationAnyUser); err != nil {
		t.Fatal(err)
	}
	workspace, err := service.CreateWorkspace(ctx, creatorID, "release-tools", "Release Tools")
	if err != nil {
		t.Fatal(err)
	}
	parsedID, err := uuid.Parse(workspace.ID)
	if err != nil || parsedID.Version() != 7 {
		t.Fatalf("PostgreSQL workspace ID is not UUIDv7: %q (%v)", workspace.ID, err)
	}
	var role string
	if err := db.QueryRowContext(ctx,
		"SELECT role FROM registry_workspace_memberships WHERE workspace_id = $1 AND user_id = $2",
		workspace.ID, creatorID).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "owner" {
		t.Fatalf("PostgreSQL did not record initial owner: %q", role)
	}
	ownerMemberships, hasMore, err := service.ListForUser(ctx, creatorID, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if hasMore || len(ownerMemberships) != 1 || ownerMemberships[0].Workspace.ID != workspace.ID ||
		ownerMemberships[0].Role != "owner" {
		t.Fatalf("PostgreSQL membership listing returned the wrong workspace scope: %+v has_more=%t",
			ownerMemberships, hasMore)
	}
	noMemberships, hasMore, err := service.ListForUser(ctx, secondCreatorID, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if hasMore || len(noMemberships) != 0 {
		t.Fatalf("PostgreSQL user without a membership saw a workspace: %+v has_more=%t", noMemberships, hasMore)
	}
	if err := service.SetMembershipRole(ctx, creatorID, workspace.ID, secondCreatorID, RoleMember); err != nil {
		t.Fatalf("PostgreSQL owner could not add a member: %v", err)
	}
	if err := service.SetMembershipRole(ctx, creatorID, workspace.ID, creatorID, RoleMember); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("PostgreSQL allowed the last owner to demote themselves: %v", err)
	}
	if err := service.SetMembershipRole(ctx, creatorID, workspace.ID, secondCreatorID, RoleOwner); err != nil {
		t.Fatalf("PostgreSQL owner could not grant a second owner: %v", err)
	}
	if err := service.RemoveMembership(ctx, creatorID, workspace.ID, creatorID); err != nil {
		t.Fatalf("PostgreSQL owner could not leave after transferring ownership: %v", err)
	}
	if err := service.RemoveMembership(ctx, secondCreatorID, workspace.ID, secondCreatorID); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("PostgreSQL allowed the remaining owner to leave: %v", err)
	}
	var remainingOwnerRole, remainingOwnerStatus string
	if err := db.QueryRowContext(ctx, `SELECT role, status FROM registry_workspace_memberships
		WHERE workspace_id = $1 AND user_id = $2`, workspace.ID, secondCreatorID).
		Scan(&remainingOwnerRole, &remainingOwnerStatus); err != nil {
		t.Fatal(err)
	}
	if remainingOwnerRole != RoleOwner || remainingOwnerStatus != "active" {
		t.Fatalf("PostgreSQL did not preserve the replacement owner: role=%q status=%q",
			remainingOwnerRole, remainingOwnerStatus)
	}
	raceWorkspace, err := service.CreateWorkspace(ctx, secondCreatorID,
		"postgres-owner-race", "PostgreSQL Owner Race")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SetMembershipRole(ctx, secondCreatorID, raceWorkspace.ID, creatorID, RoleOwner); err != nil {
		t.Fatal(err)
	}
	startOwnerRemovals := make(chan struct{})
	ownerRemovalResults := make(chan error, 2)
	for _, userID := range []string{creatorID, secondCreatorID} {
		go func(userID string) {
			<-startOwnerRemovals
			ownerRemovalResults <- service.RemoveMembership(ctx, userID, raceWorkspace.ID, userID)
		}(userID)
	}
	close(startOwnerRemovals)
	successfulOwnerRemovals := 0
	lastOwnerRejections := 0
	for range 2 {
		removeErr := <-ownerRemovalResults
		if removeErr == nil {
			successfulOwnerRemovals++
			continue
		}
		if errors.Is(removeErr, ErrLastOwner) {
			lastOwnerRejections++
			continue
		}
		t.Fatalf("unexpected PostgreSQL concurrent owner removal: %v", removeErr)
	}
	if successfulOwnerRemovals != 1 || lastOwnerRejections != 1 {
		t.Fatalf("PostgreSQL concurrent owner removal violated the invariant: succeeded=%d rejected=%d",
			successfulOwnerRemovals, lastOwnerRejections)
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE registry_workspaces SET slug = $1 WHERE workspace_id = $2", "renamed", workspace.ID); err == nil {
		t.Fatal("PostgreSQL allowed workspace slug update")
	}
	var signupPolicy string
	if err := db.QueryRowContext(ctx,
		"SELECT signup_policy FROM registry_installation WHERE singleton_id = 1").Scan(&signupPolicy); err != nil {
		t.Fatal(err)
	}
	if signupPolicy != "closed" {
		t.Fatalf("workspace policy change altered signup policy: %q", signupPolicy)
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE registry_users SET email = $1 WHERE user_id IN ($2, $3)",
		"shared@example.invalid", creatorID, secondCreatorID); err != nil {
		t.Fatal(err)
	}
	identityQuery := `INSERT INTO registry_external_identities
		(external_identity_id, user_id, provider_id, issuer, subject, created_at)
		VALUES ($1, $2, 'corp-idp', 'https://idp.example.invalid', 'stable-subject', $3)`
	if _, err := db.ExecContext(ctx, identityQuery,
		newUUID(t), creatorID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, identityQuery,
		newUUID(t), secondCreatorID, time.Now().UTC().Format(time.RFC3339Nano)); err == nil {
		t.Fatal("PostgreSQL linked one provider subject to two users")
	}

	type creationResult struct {
		workspace Workspace
		err       error
	}
	start := make(chan struct{})
	results := make(chan creationResult, 2)
	for _, userID := range []string{creatorID, secondCreatorID} {
		go func(userID string) {
			<-start
			createdWorkspace, createErr := service.CreateWorkspace(ctx, userID, "postgres-one-winner", "One Winner")
			results <- creationResult{workspace: createdWorkspace, err: createErr}
		}(userID)
	}
	close(start)
	successCount := 0
	conflictCount := 0
	for range 2 {
		result := <-results
		if result.err == nil {
			if result.workspace.ID == "" {
				t.Fatal("successful PostgreSQL workspace creation returned no identity")
			}
			successCount++
			continue
		}
		if errors.Is(result.err, ErrSlugConflict) {
			conflictCount++
			continue
		}
		t.Fatalf("unexpected concurrent PostgreSQL workspace result: %v", result.err)
	}
	if successCount != 1 || conflictCount != 1 {
		t.Fatalf("PostgreSQL workspace slug race was not serialized: succeeded=%d conflicted=%d", successCount, conflictCount)
	}
	var auditCount int
	if err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM registry_audit_events WHERE outcome = 'succeeded'").Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 9 {
		t.Fatalf("unexpected PostgreSQL audit event count: %d", auditCount)
	}
}

func seedPostgresUser(t *testing.T, ctx context.Context, db *sql.DB, status string) string {
	t.Helper()
	userID := newUUID(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_users
		(user_id, display_name, email, email_verified, status, created_at, updated_at)
		VALUES ($1, 'Postgres User', NULL, FALSE, $2, $3, $3)`, userID, status, now); err != nil {
		t.Fatal(err)
	}
	return userID
}

func seedPostgresAdmin(t *testing.T, ctx context.Context, db *sql.DB, userID string) {
	t.Helper()
	if _, err := db.ExecContext(ctx,
		"INSERT INTO registry_instance_admins (user_id, granted_by, granted_at) VALUES ($1, NULL, $2)",
		userID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}
