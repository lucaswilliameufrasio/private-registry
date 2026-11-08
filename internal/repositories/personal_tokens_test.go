package repositories

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/workspaces"
)

func TestSQLitePersonalReadTokenLifecycle(t *testing.T) {
	ctx, db, driver := openSQLite(t)
	exercisePersonalReadTokens(t, ctx, db, driver)
}

func exercisePersonalReadTokens(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver) {
	t.Helper()
	service, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	owner := seedUser(t, ctx, db, driver, true)
	user := seedUser(t, ctx, db, driver, false)
	other := seedUser(t, ctx, db, driver, false)
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "token-workspace", "Tokens")
	if err != nil {
		t.Fatal(err)
	}
	if err := workspaceService.SetMembershipRole(ctx, owner, workspace.ID, user, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	repository, err := service.Create(ctx, owner, workspace.ID, "token-repo", "Tokens")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssuePersonalReadToken(ctx, user, workspace.ID, repository.ID, time.Hour); !errors.Is(err, ErrForbidden) {
		t.Fatalf("issuance without reader grant = %v", err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, repository.ID, user, GrantReader); err != nil {
		t.Fatal(err)
	}
	if _, err := service.IssuePersonalReadToken(ctx, user, workspace.ID, repository.ID, 31*24*time.Hour); !errors.Is(err, ErrInvalidPersonalTokenRequest) {
		t.Fatalf("excessive token lifetime = %v", err)
	}
	if _, err := service.IssuePersonalReadToken(ctx, user, workspace.ID, repository.ID, time.Second); !errors.Is(err, ErrInvalidPersonalTokenRequest) {
		t.Fatalf("too-short token lifetime = %v", err)
	}
	issued, err := service.IssuePersonalReadToken(ctx, user, workspace.ID, repository.ID, time.Hour)
	if err != nil {
		t.Fatal("issue personal read token:", err)
	}
	if !strings.HasPrefix(issued.Bearer, "prp_") || len(issued.Bearer) != 84 || issued.ExpiresAt.Sub(issued.CreatedAt) != time.Hour {
		t.Fatal("issued token format or expiry is invalid")
	}
	var storedHash string
	if err := db.QueryRowContext(ctx, `SELECT secret_sha256 FROM registry_personal_read_tokens WHERE token_id = `+bind(driver, 1), issued.ID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if len(storedHash) != 64 || strings.Contains(issued.Bearer, storedHash) {
		t.Fatal("stored verifier is not a separate SHA-256 digest")
	}
	if verified, err := service.VerifyPersonalReadToken(ctx, issued.Bearer, workspace.ID, repository.ID); err != nil || verified != user {
		t.Fatal("valid personal token failed verification:", err)
	}
	if _, err := service.VerifyPersonalReadToken(ctx, issued.Bearer, workspace.ID, uuid.NewString()); !errors.Is(err, ErrPersonalTokenUnavailable) {
		t.Fatalf("token accepted for wrong repository: %v", err)
	}
	if _, err := service.VerifyPersonalReadToken(ctx, issued.Bearer+"x", workspace.ID, repository.ID); !errors.Is(err, ErrPersonalTokenUnavailable) {
		t.Fatalf("malformed token accepted: %v", err)
	}
	secretStart := len(issued.Bearer) - 43
	replacement := "A"
	if issued.Bearer[secretStart] == 'A' {
		replacement = "B"
	}
	wrong := issued.Bearer[:secretStart] + replacement + issued.Bearer[secretStart+1:]
	if _, err := service.VerifyPersonalReadToken(ctx, wrong, workspace.ID, repository.ID); !errors.Is(err, ErrPersonalTokenUnavailable) {
		t.Fatalf("wrong token secret accepted: %v", err)
	}
	revocable, err := service.IssuePersonalReadToken(ctx, user, workspace.ID, repository.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RevokePersonalReadToken(ctx, other, issued.ID); !errors.Is(err, ErrPersonalTokenUnavailable) {
		t.Fatalf("other user revoked token: %v", err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	readResult := make(chan error, 1)
	go func() {
		readResult <- service.WithPersonalReadTokenTransaction(ctx, issued.Bearer, workspace.ID, repository.ID, func(_ *sql.Tx, actor string) error {
			if actor != user {
				return errors.New("unexpected token owner")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("token transaction did not start")
	}
	revokeResult := make(chan error, 1)
	go func() {
		revokeResult <- service.RevokeRepositoryRole(ctx, owner, workspace.ID, repository.ID, user, GrantReader)
	}()
	select {
	case err := <-revokeResult:
		close(release)
		<-readResult
		t.Fatalf("grant revoked while token transaction held the lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-readResult; err != nil {
		t.Fatal(err)
	}
	if err := <-revokeResult; err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyPersonalReadToken(ctx, issued.Bearer, workspace.ID, repository.ID); !errors.Is(err, ErrPersonalTokenUnavailable) {
		t.Fatalf("token remained valid after grant revocation: %v", err)
	}
	if err := service.RevokePersonalReadToken(ctx, user, revocable.ID); err != nil {
		t.Fatal("revoke personal token after grant loss:", err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, repository.ID, user, GrantReader); err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyPersonalReadToken(ctx, issued.Bearer, workspace.ID, repository.ID); !errors.Is(err, ErrPersonalTokenUnavailable) {
		t.Fatalf("old token revived after a new grant: %v", err)
	}
	if err := service.RevokePersonalReadToken(ctx, user, issued.ID); err != nil {
		t.Fatal("revoke old token:", err)
	}
	if err := service.RevokePersonalReadToken(ctx, user, issued.ID); err != nil {
		t.Fatal("repeat token revocation:", err)
	}
	second, err := service.IssuePersonalReadToken(ctx, user, workspace.ID, repository.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_users SET status = 'suspended' WHERE user_id = `+bind(driver, 1), user); err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyPersonalReadToken(ctx, second.Bearer, workspace.ID, repository.ID); !errors.Is(err, ErrPersonalTokenUnavailable) {
		t.Fatalf("suspended account token accepted: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_users SET status = 'active' WHERE user_id = `+bind(driver, 1), user); err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyPersonalReadToken(ctx, second.Bearer, workspace.ID, repository.ID); !errors.Is(err, ErrPersonalTokenUnavailable) {
		t.Fatalf("suspended token revived on account reactivation: %v", err)
	}
	third, err := service.IssuePersonalReadToken(ctx, user, workspace.ID, repository.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Expire deterministically without logging or printing the bearer.
	if _, err := db.ExecContext(ctx, `UPDATE registry_personal_read_tokens SET created_at_ms = 0, expires_at_ms = 1 WHERE token_id = `+bind(driver, 1), third.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyPersonalReadToken(ctx, third.Bearer, workspace.ID, repository.ID); !errors.Is(err, ErrPersonalTokenUnavailable) {
		t.Fatalf("expired personal token accepted: %v", err)
	}
	listed, more, err := service.ListPersonalReadTokens(ctx, user, "", 2)
	if err != nil || !more || len(listed) != 2 {
		t.Fatalf("personal token pagination returned %d entries, more=%t, err=%v", len(listed), more, err)
	}
	last, more, err := service.ListPersonalReadTokens(ctx, user, listed[1].ID, 2)
	if err != nil || more || len(last) != 2 {
		t.Fatalf("personal token second page returned %d entries, more=%t, err=%v", len(last), more, err)
	}
}
