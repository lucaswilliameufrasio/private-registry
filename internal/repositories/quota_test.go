package repositories

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"private-registry/internal/config"
	"private-registry/internal/workspaces"
)

func TestSQLiteLogicalQuotaAdministration(t *testing.T) {
	ctx, db, driver := openSQLite(t)
	service, err := New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	workspacesService, err := workspaces.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	admin := seedUser(t, ctx, db, driver, true)
	member := seedUser(t, ctx, db, driver, false)
	workspace, err := workspacesService.CreateWorkspace(ctx, admin, "quota-admin", "Quota")
	if err != nil {
		t.Fatal(err)
	}
	repository, err := service.Create(ctx, admin, workspace.ID, "quota", "Quota")
	if err != nil {
		t.Fatal(err)
	}
	exerciseQuotaAdministration(t, ctx, db, service, driver, admin, member, workspace.ID, repository.ID)
}

func exerciseQuotaAdministration(t *testing.T, ctx context.Context, db *sql.DB, service *Service, driver config.DatabaseDriver, admin, member, workspace, repository string) {
	t.Helper()
	if _, err := service.LogicalQuotaPolicy(ctx, member, workspace, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin quota read = %v", err)
	}
	value := int64(5)
	if _, err := service.SetLogicalQuotaPolicy(ctx, member, workspace, "", 0, &value); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin quota write = %v", err)
	}
	initial, err := service.LogicalQuotaPolicy(ctx, admin, workspace, "")
	if err != nil || initial.Revision != 0 || initial.LimitBytes != nil {
		t.Fatalf("initial quota = %+v, %v", initial, err)
	}
	type result struct {
		policy LogicalQuota
		err    error
	}
	results := make(chan result, 2)
	for _, limit := range []int64{10, 20} {
		limit := limit
		go func() {
			policy, err := service.SetLogicalQuotaPolicy(ctx, admin, workspace, "", 0, &limit)
			results <- result{policy, err}
		}()
	}
	var applied, stale int
	for range 2 {
		got := <-results
		if got.err == nil && got.policy.Revision == 1 {
			applied++
		} else if errors.Is(got.err, ErrQuotaRevision) {
			stale++
		} else {
			t.Fatalf("concurrent quota update = %+v, %v", got.policy, got.err)
		}
	}
	if applied != 1 || stale != 1 {
		t.Fatalf("concurrent quota results: applied=%d stale=%d", applied, stale)
	}
	updated, err := service.LogicalQuotaPolicy(ctx, admin, workspace, "")
	if err != nil || updated.Revision != 1 || updated.LimitBytes == nil {
		t.Fatalf("updated quota = %+v, %v", updated, err)
	}
	same, err := service.SetLogicalQuotaPolicy(ctx, admin, workspace, "", 1, updated.LimitBytes)
	if err != nil || same.Revision != 1 {
		t.Fatalf("no-op quota update = %+v, %v", same, err)
	}
	cleared, err := service.SetLogicalQuotaPolicy(ctx, admin, workspace, "", 1, nil)
	if err != nil || cleared.Revision != 2 || cleared.LimitBytes != nil {
		t.Fatalf("clear quota = %+v, %v", cleared, err)
	}
	zero := int64(0)
	repoPolicy, err := service.SetLogicalQuotaPolicy(ctx, admin, workspace, repository, 0, &zero)
	if err != nil || repoPolicy.Revision != 1 || repoPolicy.LimitBytes == nil || *repoPolicy.LimitBytes != 0 {
		t.Fatalf("repository zero quota = %+v, %v", repoPolicy, err)
	}
	var auditCount int
	query := `SELECT count(*) FROM registry_audit_events WHERE action = 'logical_quota.changed' AND actor_user_id = ` + bind(driver, 1)
	if err := db.QueryRowContext(ctx, query, admin).Scan(&auditCount); err != nil || auditCount != 3 {
		t.Fatalf("quota audit count = %d, %v; want 3", auditCount, err)
	}
}
