package artifacts

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
)

func TestSQLiteGenericQuotaReservations(t *testing.T) {
	fixture := newArtifactFixture(t)
	exerciseGenericQuota(t, fixture.service, fixture.db, config.SQLite, fixture.userIDs["publisher"], fixture.workspaceID, fixture.repositoryID)
}

func exerciseGenericQuota(t *testing.T, service *Service, db *sql.DB, driver config.DatabaseDriver, actor, workspace, repository string) {
	t.Helper()
	ctx := context.Background()
	bindArg := func(n int) string {
		if driver == config.Postgres {
			return fmt.Sprintf("$%d", n)
		}
		return "?"
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_workspaces SET logical_quota_bytes = 5 WHERE workspace_id = `+bindArg(1), workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET logical_quota_bytes = 5 WHERE repository_id = `+bindArg(1), repository); err != nil {
		t.Fatal(err)
	}
	payload := []byte("same")
	type result struct {
		session UploadSession
		err     error
	}
	results := make(chan result, 2)
	for _, version := range []string{"v1", "v2"} {
		request := requestFor("quota", version, "same.bin", payload)
		go func() {
			session, err := service.StartUpload(ctx, actor, workspace, repository, request)
			results <- result{session, err}
		}()
	}
	var winner UploadSession
	var successes, denied int
	for range 2 {
		got := <-results
		if got.err == nil {
			winner = got.session
			successes++
		} else if errors.Is(got.err, ErrLogicalQuotaExceeded) {
			denied++
		} else {
			t.Fatalf("quota reservation failed unexpectedly: %v", got.err)
		}
	}
	if successes != 1 || denied != 1 {
		t.Fatalf("quota reservations: %d successes, %d rejected; want one each", successes, denied)
	}
	if _, err := service.ReceiveUpload(ctx, actor, workspace, repository, winner.ID, bytes.NewReader(payload)); err != nil {
		t.Fatal("receive reserved bytes:", err)
	}
	if _, err := service.Publish(ctx, actor, workspace, repository, winner.ArtifactVersionID); err != nil {
		t.Fatal("publish reserved bytes:", err)
	}
	if _, err := service.StartUpload(ctx, actor, workspace, repository, requestFor("other", "v1", "same.bin", payload)); !errors.Is(err, ErrLogicalQuotaExceeded) {
		t.Fatalf("published logical bytes did not count toward quota: %v", err)
	}
	var owner, createdAt string
	if err := db.QueryRowContext(ctx, `SELECT created_by, created_at FROM registry_repositories WHERE repository_id = `+bindArg(1), repository).Scan(&owner, &createdAt); err != nil {
		t.Fatal(err)
	}
	otherRepository := uuid.NewString()
	query := `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, visibility, status, created_by, created_at, updated_at) VALUES (` + bindArg(1) + `, ` + bindArg(2) + `, 'quota-other', 'Other', 'private', 'active', ` + bindArg(3) + `, ` + bindArg(4) + `, ` + bindArg(5) + `)`
	if _, err := db.ExecContext(ctx, query, otherRepository, workspace, owner, createdAt, createdAt); err != nil {
		t.Fatal("seed second repository:", err)
	}
	query = `INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (` + bindArg(1) + `, ` + bindArg(2) + `, ` + bindArg(3) + `, ` + bindArg(4) + `, 'publisher', ` + bindArg(5) + `, ` + bindArg(6) + `)`
	if _, err := db.ExecContext(ctx, query, uuid.NewString(), otherRepository, workspace, actor, owner, createdAt); err != nil {
		t.Fatal("seed second repository grant:", err)
	}
	if _, err := service.StartUpload(ctx, actor, workspace, otherRepository, requestFor("cross-repository", "v1", "same.bin", payload)); !errors.Is(err, ErrLogicalQuotaExceeded) {
		t.Fatalf("workspace quota did not span repositories: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_workspaces SET logical_quota_bytes = 3 WHERE workspace_id = `+bindArg(1), workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := service.StartUpload(ctx, actor, workspace, repository, requestFor("other", "v1", "empty", nil)); err != nil {
		t.Fatalf("zero-byte upload should not grow usage over lowered limit: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_workspaces SET logical_quota_bytes = 10 WHERE workspace_id = `+bindArg(1), workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := service.StartUpload(ctx, actor, workspace, repository, requestFor("other", "v1", "same.bin", payload)); !errors.Is(err, ErrLogicalQuotaExceeded) {
		t.Fatalf("repository limit was not enforced independently: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET logical_quota_bytes = 10 WHERE repository_id = `+bindArg(1), repository); err != nil {
		t.Fatal(err)
	}
	expiring, err := service.StartUpload(ctx, actor, workspace, repository, requestFor("other", "v1", "same.bin", payload))
	if err != nil {
		t.Fatal("reserve remaining quota:", err)
	}
	if _, err := service.StartUpload(ctx, actor, workspace, repository, requestFor("third", "v1", "same.bin", payload)); !errors.Is(err, ErrLogicalQuotaExceeded) {
		t.Fatalf("unfinished reservation did not count: %v", err)
	}
	old := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	query = `UPDATE registry_generic_upload_sessions SET expires_at = ` + bindArg(1) + ` WHERE upload_session_id = ` + bindArg(2)
	if _, err := db.ExecContext(ctx, query, old, expiring.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ExpireUploadBatch(ctx, time.Now().UTC(), 10); err != nil {
		t.Fatal("expire unused reservation:", err)
	}
	if _, err := service.StartUpload(ctx, actor, workspace, repository, requestFor("third", "v1", "same.bin", payload)); err != nil {
		t.Fatalf("expired reservation did not release quota: %v", err)
	}
}
