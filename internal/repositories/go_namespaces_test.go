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

func TestSQLiteGoNamespacePolicy(t *testing.T) {
	ctx, db, driver := openSQLite(t)
	exerciseGoNamespacePolicy(t, ctx, db, driver)
}

func exerciseGoNamespacePolicy(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver) {
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
	owner, reader, member := seedUser(t, ctx, db, driver, true), seedUser(t, ctx, db, driver, false), seedUser(t, ctx, db, driver, false)
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "go-namespace-test", "Go namespace test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateWithFormat(ctx, owner, workspace.ID, "cargo-disabled", "Cargo disabled", Format("cargo")); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("unsupported Cargo format became available before its adapter: %v", err)
	}
	for _, user := range []string{reader, member} {
		if err := workspaceService.SetMembershipRole(ctx, owner, workspace.ID, user, workspaces.RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	repo, err := service.CreateWithFormat(ctx, owner, workspace.ID, "modules", "Go", FormatGo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.GrantRepositoryRole(ctx, owner, workspace.ID, repo.ID, reader, GrantReader); err != nil {
		t.Fatal(err)
	}
	policy, err := service.GoNamespacePolicy(ctx, owner, workspace.ID, repo.ID)
	if err != nil || policy.Mode != "private_all" || len(policy.Prefixes) != 0 || policy.Revision != 0 {
		t.Fatalf("default Go namespace policy=%+v err=%v", policy, err)
	}
	if private, err := service.IsGoPrivateNamespace(ctx, reader, workspace.ID, repo.ID, "example.net/public"); err != nil || !private {
		t.Fatalf("default namespace not private: private=%t err=%v", private, err)
	}
	if _, err := service.GoNamespacePolicy(ctx, member, workspace.ID, repo.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member read Go namespace policy: %v", err)
	}
	if _, err := service.SetGoNamespacePolicy(ctx, owner, workspace.ID, repo.ID, 0, "private_prefixes", []string{"example.com/private"}, false); !errors.Is(err, ErrGoNamespaceConfirm) {
		t.Fatalf("public fallback accepted without confirmation: %v", err)
	}
	if _, err := service.SetGoNamespacePolicy(ctx, member, workspace.ID, repo.ID, 0, "private_prefixes", []string{"example.com/private"}, true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member changed Go namespace policy: %v", err)
	}
	policy, err = service.SetGoNamespacePolicy(ctx, owner, workspace.ID, repo.ID, 0, "private_prefixes", []string{"example.com/private"}, true)
	if err != nil || policy.Revision != 1 {
		t.Fatalf("set Go namespace policy=%+v err=%v", policy, err)
	}
	for _, item := range []struct {
		path    string
		private bool
	}{{"example.com", true}, {"example.com/private", true}, {"example.com/private/module", true}, {"example.com/private-other", false}, {"example.com/public", false}, {"example.net/public", false}} {
		private, err := service.IsGoPrivateNamespace(ctx, reader, workspace.ID, repo.ID, item.path)
		if err != nil || private != item.private {
			t.Fatalf("namespace %q private=%t want=%t err=%v", item.path, private, item.private, err)
		}
	}
	if private, err := service.IsGoPrivateNamespace(ctx, member, workspace.ID, repo.ID, "example.net/public"); !errors.Is(err, ErrForbidden) || !private {
		t.Fatalf("unauthorized namespace classification private=%t err=%v", private, err)
	}
	if _, err := service.SetGoNamespacePolicy(ctx, owner, workspace.ID, repo.ID, 0, "private_all", nil, false); !errors.Is(err, ErrGoNamespaceRevision) {
		t.Fatalf("stale namespace policy update accepted: %v", err)
	}
	query := `INSERT INTO registry_go_module_versions (module_version_id, workspace_id, repository_id, module_path, version, mod_bytes, zip_sha256, zip_size, source_time, created_by, created_at) VALUES (` + bind(driver, 1) + `, ` + bind(driver, 2) + `, ` + bind(driver, 3) + `, 'example.com/private/existing', 'v1.0.0', ` + bind(driver, 4) + `, ` + bind(driver, 5) + `, 1, ` + bind(driver, 6) + `, ` + bind(driver, 7) + `, ` + bind(driver, 8) + `)`
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx, query, uuid.NewString(), workspace.ID, repo.ID, []byte("module example.com/private/existing\n"), strings.Repeat("a", 64), now, owner, now); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetGoNamespacePolicy(ctx, owner, workspace.ID, repo.ID, 1, "private_prefixes", []string{"example.com/other"}, true); !errors.Is(err, ErrGoNamespaceInUse) {
		t.Fatalf("namespace update exposed known private identity: %v", err)
	}
	policy, err = service.GoNamespacePolicy(ctx, owner, workspace.ID, repo.ID)
	if err != nil || policy.Revision != 1 || len(policy.Prefixes) != 1 || policy.Prefixes[0] != "example.com/private" {
		t.Fatalf("rejected policy update changed state: %+v err=%v", policy, err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_namespace_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'go.namespace_policy.changed' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := service.SetGoNamespacePolicy(ctx, owner, workspace.ID, repo.ID, 1, "private_all", nil, false); err == nil {
			t.Fatal("namespace change succeeded without audit")
		}
		policy, err := service.GoNamespacePolicy(ctx, owner, workspace.ID, repo.ID)
		if err != nil || policy.Mode != "private_prefixes" || policy.Revision != 1 {
			t.Fatalf("failed namespace audit changed policy: %+v err=%v", policy, err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_namespace_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	results := make(chan error, 2)
	go func() {
		_, err := service.SetGoNamespacePolicy(ctx, owner, workspace.ID, repo.ID, 1, "private_all", nil, false)
		results <- err
	}()
	go func() {
		_, err := service.SetGoNamespacePolicy(ctx, owner, workspace.ID, repo.ID, 1, "private_prefixes", []string{"example.com/private", "example.net/private"}, true)
		results <- err
	}()
	var succeeded, stale int
	for range 2 {
		err := <-results
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrGoNamespaceRevision) {
			stale++
		} else {
			t.Fatalf("concurrent namespace change failed: %v", err)
		}
	}
	if succeeded != 1 || stale != 1 {
		t.Fatalf("concurrent namespace changes: succeeded=%d stale=%d", succeeded, stale)
	}
	policy, err = service.GoNamespacePolicy(ctx, owner, workspace.ID, repo.ID)
	if err != nil || policy.Revision != 2 {
		t.Fatalf("concurrent namespace revision: %+v err=%v", policy, err)
	}
}
