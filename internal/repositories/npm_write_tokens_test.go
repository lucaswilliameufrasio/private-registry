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

func TestSQLiteNPMWriteTokenLifecycle(t *testing.T) {
	ctx, db, driver := openSQLite(t)
	exerciseNPMWriteTokenLifecycle(t, ctx, db, driver)
}

func exerciseNPMWriteTokenLifecycle(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	service, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	workspacesService, err := workspaces.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	owner, user, other := seedUser(t, ctx, db, driver, true), seedUser(t, ctx, db, driver, false), seedUser(t, ctx, db, driver, false)
	workspace, err := workspacesService.CreateWorkspace(ctx, owner, "npm-write-token", "npm write token")
	if err != nil {
		t.Fatal(err)
	}
	if err := workspacesService.SetMembershipRole(ctx, owner, workspace.ID, user, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	query := `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, 'npm', 'npm', ` + bind(driver, 3) + `, 'now', 'now', 'npm')`
	if _, err := db.ExecContext(ctx, query, repository, workspace.ID, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueNPMWriteToken(ctx, user, workspace.ID, repository, time.Hour); !errors.Is(err, ErrForbidden) {
		t.Fatalf("issuance without publisher grant: %v", err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, repository, user, GrantPublisher); err != nil {
		t.Fatal(err)
	}
	generic, err := service.Create(ctx, owner, workspace.ID, "npm-token-generic", "Generic")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, generic.ID, user, GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssueNPMWriteToken(ctx, user, workspace.ID, generic.ID, time.Hour); !errors.Is(err, ErrNPMWriteTokenUnavailable) {
		t.Fatalf("npm credential issued for generic repository: %v", err)
	}
	for _, ttl := range []time.Duration{time.Second, 31 * 24 * time.Hour} {
		if _, err := service.IssueNPMWriteToken(ctx, user, workspace.ID, repository, ttl); !errors.Is(err, ErrInvalidPersonalTokenRequest) {
			t.Fatalf("invalid credential lifetime accepted: %v", err)
		}
	}
	issued, err := service.IssueNPMWriteToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var verifier string
	if err := db.QueryRowContext(ctx, `SELECT secret_sha256 FROM registry_npm_write_tokens WHERE token_id = `+bind(driver, 1), issued.ID).Scan(&verifier); err != nil || len(verifier) != 64 {
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
	if err := service.WithNPMWriteTokenTransaction(ctx, issued.Bearer, workspace.ID, repository, apply); err != nil || !called {
		t.Fatalf("valid npm credential rejected: %v", err)
	}
	callbackErr := errors.New("synthetic callback failure")
	if err := service.WithNPMWriteTokenTransaction(ctx, issued.Bearer, workspace.ID, repository, func(tx *sql.Tx, _ string) error {
		if _, err := tx.ExecContext(ctx, `UPDATE registry_repositories SET display_name = 'changed' WHERE repository_id = `+bind(driver, 1), repository); err != nil {
			return err
		}
		return callbackErr
	}); !errors.Is(err, callbackErr) {
		t.Fatalf("callback failure not propagated: %v", err)
	}
	var displayName string
	if err := db.QueryRowContext(ctx, `SELECT display_name FROM registry_repositories WHERE repository_id = `+bind(driver, 1), repository).Scan(&displayName); err != nil || displayName != "npm" {
		t.Fatalf("failed credential callback was not rolled back: %v", err)
	}
	secretStart := len(issued.Bearer) - 43
	replacement := "A"
	if issued.Bearer[secretStart] == 'A' {
		replacement = "B"
	}
	wrong := issued.Bearer[:secretStart] + replacement + issued.Bearer[secretStart+1:]
	if err := service.WithNPMWriteTokenTransaction(ctx, wrong, workspace.ID, repository, apply); !errors.Is(err, ErrNPMWriteTokenUnavailable) {
		t.Fatalf("wrong credential secret accepted: %v", err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, repository, user, GrantReader); err != nil {
		t.Fatal(err)
	}
	readToken, err := service.IssuePersonalReadToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.WithNPMWriteTokenTransaction(ctx, readToken.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrNPMWriteTokenUnavailable) {
		t.Fatalf("read credential accepted for npm writing: %v", err)
	}
	if _, err := service.VerifyPersonalReadToken(ctx, issued.Bearer, workspace.ID, repository); !errors.Is(err, ErrPersonalTokenUnavailable) {
		t.Fatalf("npm write credential accepted for reading: %v", err)
	}
	called = false
	if err := service.WithNPMWriteTokenTransaction(ctx, issued.Bearer, workspace.ID, uuid.NewString(), apply); !errors.Is(err, ErrNPMWriteTokenUnavailable) || called {
		t.Fatalf("cross-repository credential accepted: %v", err)
	}
	if err := service.RevokeNPMWriteToken(ctx, other, issued.ID); !errors.Is(err, ErrNPMWriteTokenUnavailable) {
		t.Fatalf("other user revoked npm credential: %v", err)
	}
	if err := service.RevokeRepositoryRole(ctx, owner, workspace.ID, repository, user, GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, repository, user, GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if err := service.WithNPMWriteTokenTransaction(ctx, issued.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrNPMWriteTokenUnavailable) {
		t.Fatalf("credential survived grant revocation and regrant: %v", err)
	}
	if err := service.RevokeNPMWriteToken(ctx, user, issued.ID); err != nil {
		t.Fatal(err)
	}
	expiring, err := service.IssueNPMWriteToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_npm_write_tokens SET created_at_ms = 1, expires_at_ms = 2 WHERE token_id = `+bind(driver, 1), expiring.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.WithNPMWriteTokenTransaction(ctx, expiring.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrNPMWriteTokenUnavailable) {
		t.Fatalf("expired credential accepted: %v", err)
	}
	if err := service.RevokeNPMWriteToken(ctx, user, issued.ID); err != nil {
		t.Fatal(err)
	}
	second, err := service.IssueNPMWriteToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	firstPage, more, err := service.ListNPMWriteTokens(ctx, user, "", 1)
	if err != nil || !more || len(firstPage) != 1 || firstPage[0].WorkspaceID != workspace.ID || firstPage[0].RepositoryID != repository {
		t.Fatalf("npm credential metadata pagination failed: %v", err)
	}
	secondPage, _, err := service.ListNPMWriteTokens(ctx, user, firstPage[0].ID, 100)
	if err != nil || len(secondPage) < 1 {
		t.Fatalf("npm credential metadata next page failed: %v", err)
	}
	otherItems, _, err := service.ListNPMWriteTokens(ctx, other, "", 100)
	if err != nil || len(otherItems) != 0 {
		t.Fatalf("credential metadata leaked to another user: %v", err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	useResult := make(chan error, 1)
	go func() {
		useResult <- service.WithNPMWriteTokenTransaction(ctx, second.Bearer, workspace.ID, repository, func(_ *sql.Tx, _ string) error {
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
		t.Fatal("npm credential transaction did not start")
	}
	grantResult := make(chan error, 1)
	go func() {
		grantResult <- service.RevokeRepositoryRole(ctx, owner, workspace.ID, repository, user, GrantPublisher)
	}()
	select {
	case err := <-grantResult:
		close(release)
		<-useResult
		t.Fatalf("grant revoked during npm credential transaction: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-useResult; err != nil {
		t.Fatalf("npm credential transaction failed: %v", err)
	}
	if err := <-grantResult; err != nil {
		t.Fatalf("publisher grant revocation failed: %v", err)
	}
	if err := service.WithNPMWriteTokenTransaction(ctx, second.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrNPMWriteTokenUnavailable) {
		t.Fatalf("npm credential survived serialized grant revocation: %v", err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, repository, user, GrantPublisher); err != nil {
		t.Fatal(err)
	}
	second, err = service.IssueNPMWriteToken(ctx, user, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_users SET status = 'suspended' WHERE user_id = `+bind(driver, 1), user); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_users SET status = 'active' WHERE user_id = `+bind(driver, 1), user); err != nil {
		t.Fatal(err)
	}
	if err := service.WithNPMWriteTokenTransaction(ctx, second.Bearer, workspace.ID, repository, apply); !errors.Is(err, ErrNPMWriteTokenUnavailable) {
		t.Fatalf("credential revived after suspension: %v", err)
	}
}
