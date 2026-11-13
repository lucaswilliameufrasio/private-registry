package repositories

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/workspaces"
)

func TestSQLiteCargoWriteTokenLifecycle(t *testing.T) {
	ctx, db, driver := openSQLite(t)
	exerciseCargoWriteTokenLifecycle(t, ctx, db, driver)
}

func exerciseCargoWriteTokenLifecycle(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	service, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	owner, user, other := seedUser(t, ctx, db, driver, true), seedUser(t, ctx, db, driver, false), seedUser(t, ctx, db, driver, false)
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "cargo-write-token", "Cargo write token")
	if err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, owner, workspace.ID, user, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	query := `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, 'cargo', 'Cargo', ` + bind(driver, 3) + `, 'now', 'now', 'cargo')`
	if _, err := db.ExecContext(ctx, query, repository, workspace.ID, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueCargoWriteToken(ctx, user, workspace.ID, repository, time.Hour); !errors.Is(err, ErrForbidden) {
		t.Fatalf("issuance without publisher grant: %v", err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, repository, user, GrantPublisher); err != nil {
		t.Fatal(err)
	}
	generic, err := service.Create(ctx, owner, workspace.ID, "generic-write-token", "Generic")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, generic.ID, user, GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueCargoWriteToken(ctx, user, workspace.ID, generic.ID, time.Hour); !errors.Is(err, ErrCargoWriteTokenUnavailable) {
		t.Fatalf("Cargo credential issued for generic repository: %v", err)
	}
	if _, err := service.IssueCargoWriteToken(ctx, user, workspace.ID, repository, time.Second); !errors.Is(err, ErrInvalidPersonalTokenRequest) {
		t.Fatalf("too-short credential lifetime accepted: %v", err)
	}
	if _, err := service.IssueCargoWriteToken(ctx, user, workspace.ID, repository, 31*24*time.Hour); !errors.Is(err, ErrInvalidPersonalTokenRequest) {
		t.Fatalf("excessive credential lifetime accepted: %v", err)
	}
	issued, err := service.IssueCargoWriteToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var verifier string
	if err := db.QueryRowContext(ctx, `SELECT secret_sha256 FROM registry_cargo_write_tokens WHERE token_id = `+bind(driver, 1), issued.ID).Scan(&verifier); err != nil || len(verifier) != 64 {
		t.Fatalf("credential verifier missing or invalid: %v", err)
	}
	called := false
	apply := func(_ *sql.Tx, actor string) error {
		called = true
		if actor != user {
			t.Fatal("wrong credential owner")
		}
		return nil
	}
	if err := service.WithCargoWriteTokenTransaction(ctx, issued.Bearer, workspace.ID, repository, apply); err != nil || !called {
		t.Fatalf("valid credential rejected: %v", err)
	}
	rollbackErr := errors.New("synthetic callback failure")
	if err := service.WithCargoWriteTokenTransaction(ctx, issued.Bearer, workspace.ID, repository, func(tx *sql.Tx, _ string) error {
		if _, err := tx.ExecContext(ctx, `UPDATE registry_repositories SET display_name = 'changed' WHERE repository_id = `+bind(driver, 1), repository); err != nil {
			return err
		}
		return rollbackErr
	}); !errors.Is(err, rollbackErr) {
		t.Fatalf("callback failure not propagated: %v", err)
	}
	var displayName string
	if err := db.QueryRowContext(ctx, `SELECT display_name FROM registry_repositories WHERE repository_id = `+bind(driver, 1), repository).Scan(&displayName); err != nil || displayName != "Cargo" {
		t.Fatalf("failed callback was not rolled back: %v", err)
	}
	secretStart := len(issued.Bearer) - 43
	replacement := "A"
	if issued.Bearer[secretStart] == 'A' {
		replacement = "B"
	}
	incorrect := issued.Bearer[:secretStart] + replacement + issued.Bearer[secretStart+1:]
	if err := service.WithCargoWriteTokenTransaction(ctx, incorrect, workspace.ID, repository, apply); !errors.Is(err, ErrCargoWriteTokenUnavailable) {
		t.Fatalf("incorrect secret accepted: %v", err)
	}
	called = false
	if err := service.WithCargoWriteTokenTransaction(ctx, issued.Bearer, workspace.ID, uuid.NewString(), apply); !errors.Is(err, ErrCargoWriteTokenUnavailable) || called {
		t.Fatalf("cross-repository credential accepted: %v", err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, repository, user, GrantReader); err != nil {
		t.Fatal(err)
	}
	readToken, err := service.IssuePersonalReadToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.WithCargoWriteTokenTransaction(ctx, readToken.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrCargoWriteTokenUnavailable) {
		t.Fatalf("read credential accepted for writing: %v", err)
	}
	if _, err := service.VerifyPersonalReadToken(ctx, issued.Bearer, workspace.ID, repository); !errors.Is(err, ErrPersonalTokenUnavailable) {
		t.Fatalf("write credential accepted for reading: %v", err)
	}
	if err := service.RevokeCargoWriteToken(ctx, other, issued.ID); !errors.Is(err, ErrCargoWriteTokenUnavailable) {
		t.Fatalf("other user revoked credential: %v", err)
	}
	if err := service.RevokeRepositoryRole(ctx, owner, workspace.ID, repository, user, GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if err := service.WithCargoWriteTokenTransaction(ctx, issued.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrCargoWriteTokenUnavailable) {
		t.Fatalf("credential survived grant revocation: %v", err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, repository, user, GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if err := service.WithCargoWriteTokenTransaction(ctx, issued.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrCargoWriteTokenUnavailable) {
		t.Fatalf("credential revived after regrant: %v", err)
	}
	if err := service.RevokeCargoWriteToken(ctx, user, issued.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.RevokeCargoWriteToken(ctx, user, issued.ID); err != nil {
		t.Fatal(err)
	}
	second, err := service.IssueCargoWriteToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RevokeCargoWriteToken(ctx, user, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.WithCargoWriteTokenTransaction(ctx, second.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrCargoWriteTokenUnavailable) {
		t.Fatalf("explicitly revoked credential accepted: %v", err)
	}
	third, err := service.IssueCargoWriteToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_users SET status = 'suspended' WHERE user_id = `+bind(driver, 1), user); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_users SET status = 'active' WHERE user_id = `+bind(driver, 1), user); err != nil {
		t.Fatal(err)
	}
	if err := service.WithCargoWriteTokenTransaction(ctx, third.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrCargoWriteTokenUnavailable) {
		t.Fatalf("credential revived after suspension: %v", err)
	}
	fourth, err := service.IssueCargoWriteToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_write_tokens SET created_at_ms = 0, expires_at_ms = 1 WHERE token_id = `+bind(driver, 1), fourth.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.WithCargoWriteTokenTransaction(ctx, fourth.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrCargoWriteTokenUnavailable) {
		t.Fatalf("expired credential accepted: %v", err)
	}
	fifth, err := service.IssueCargoWriteToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	useResult := make(chan error, 1)
	go func() {
		useResult <- service.WithCargoWriteTokenTransaction(ctx, fifth.Bearer, workspace.ID, repository, func(_ *sql.Tx, _ string) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("credential transaction did not start")
	}
	revokeStarted := make(chan struct{})
	revokeResult := make(chan error, 1)
	go func() {
		close(revokeStarted)
		revokeResult <- service.RevokeCargoWriteToken(ctx, user, fifth.ID)
	}()
	<-revokeStarted
	select {
	case err := <-revokeResult:
		close(release)
		<-useResult
		t.Fatalf("revocation completed while credential transaction held lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-useResult; err != nil {
		t.Fatalf("credential transaction failed: %v", err)
	}
	if err := <-revokeResult; err != nil {
		t.Fatalf("credential revocation failed: %v", err)
	}
	if err := service.WithCargoWriteTokenTransaction(ctx, fifth.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrCargoWriteTokenUnavailable) {
		t.Fatalf("credential usable after serialized revocation: %v", err)
	}
	listed, more, err := service.ListCargoWriteTokens(ctx, user, "", 2)
	if err != nil || !more || len(listed) != 2 {
		t.Fatalf("credential pagination failed: count=%d more=%t err=%v", len(listed), more, err)
	}
	others, _, err := service.ListCargoWriteTokens(ctx, other, "", 100)
	if err != nil || len(others) != 0 {
		t.Fatalf("other user's credentials were visible: count=%d err=%v", len(others), err)
	}
	var audit int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events WHERE target_type = 'cargo_write_token' AND target_id = `+bind(driver, 1), fifth.ID).Scan(&audit); err != nil || audit != 2 {
		t.Fatalf("credential creation and revocation were not audited: count=%d err=%v", audit, err)
	}
	sixth, err := service.IssueCargoWriteToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.RemoveMembership(ctx, owner, workspace.ID, user); err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, owner, workspace.ID, user, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, repository, user, GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if err := service.WithCargoWriteTokenTransaction(ctx, sixth.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrCargoWriteTokenUnavailable) {
		t.Fatalf("credential revived after membership removal: %v", err)
	}
	seventh, err := service.IssueCargoWriteToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	enteredGrant := make(chan struct{})
	releaseGrant := make(chan struct{})
	useGrantResult := make(chan error, 1)
	go func() {
		useGrantResult <- service.WithCargoWriteTokenTransaction(ctx, seventh.Bearer, workspace.ID, repository, func(_ *sql.Tx, _ string) error {
			close(enteredGrant)
			select {
			case <-releaseGrant:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-enteredGrant:
	case <-ctx.Done():
		t.Fatal("credential transaction did not start")
	}
	grantResult := make(chan error, 1)
	go func() {
		grantResult <- service.RevokeRepositoryRole(ctx, owner, workspace.ID, repository, user, GrantPublisher)
	}()
	select {
	case err := <-grantResult:
		close(releaseGrant)
		<-useGrantResult
		t.Fatalf("grant revoked while credential transaction held lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseGrant)
	if err := <-useGrantResult; err != nil {
		t.Fatalf("credential transaction failed: %v", err)
	}
	if err := <-grantResult; err != nil {
		t.Fatalf("publisher grant revocation failed: %v", err)
	}
	if err := service.WithCargoWriteTokenTransaction(ctx, seventh.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrCargoWriteTokenUnavailable) {
		t.Fatalf("credential remained usable after serialized grant revocation: %v", err)
	}
}
