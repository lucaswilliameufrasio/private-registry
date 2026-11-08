//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/testinfra"
)

func TestMigratePostgresRealDatabaseAndAdvisoryLock(t *testing.T) {
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
	firstDB, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := firstDB.Close(); err != nil {
			t.Errorf("close first PostgreSQL connection: %v", err)
		}
	})
	secondDB, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := secondDB.Close(); err != nil {
			t.Errorf("close second PostgreSQL connection: %v", err)
		}
	})

	type migrationResult struct {
		report Report
		err    error
	}
	start := make(chan struct{})
	results := make(chan migrationResult, 2)
	for _, db := range []*sql.DB{firstDB, secondDB} {
		go func(db *sql.DB) {
			<-start
			report, err := Migrate(ctx, db, cfg)
			results <- migrationResult{report: report, err: err}
		}(db)
	}
	close(start)
	var first Report
	var installationID string
	appliedCount := 0
	var migrationErrors []error
	for range 2 {
		result := <-results
		if result.err != nil {
			migrationErrors = append(migrationErrors, result.err)
			continue
		}
		if result.report.CurrentVersion != 21 || result.report.TargetVersion != 21 || result.report.InstallationID == "" {
			migrationErrors = append(migrationErrors, errors.New("unexpected concurrent PostgreSQL migration report"))
			continue
		}
		if installationID == "" {
			installationID = result.report.InstallationID
		} else if result.report.InstallationID != installationID {
			migrationErrors = append(migrationErrors, errors.New("concurrent migrations created different installation identities"))
		}
		if len(result.report.AppliedVersions) == 21 {
			first = result.report
			appliedCount++
		} else if len(result.report.AppliedVersions) != 0 {
			migrationErrors = append(migrationErrors, errors.New("concurrent migration applied an unexpected version count"))
		}
	}
	if err := errors.Join(migrationErrors...); err != nil {
		t.Fatal(err)
	}
	if appliedCount != 1 || first.CurrentVersion != 21 || first.TargetVersion != 21 || first.InstallationID == "" {
		t.Fatalf("PostgreSQL advisory lock did not serialize migration callers: first=%+v applied=%d", first, appliedCount)
	}
	if err := VerifyCurrent(ctx, firstDB, config.Postgres, first.InstallationID); err != nil {
		t.Fatal("verify PostgreSQL migration history:", err)
	}
	if err := VerifyCurrent(ctx, firstDB, config.Postgres, "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("PostgreSQL verification accepted wrong installation identity")
	}

	var attempts int
	if err := firstDB.QueryRowContext(ctx,
		"SELECT count(*) FROM registry_migration_attempts WHERE status = 'succeeded'").Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 21 {
		t.Fatalf("unexpected successful PostgreSQL migration attempts: %d", attempts)
	}
	var checksumCount int
	if err := firstDB.QueryRowContext(ctx,
		"SELECT count(*) FROM registry_migration_checksums").Scan(&checksumCount); err != nil {
		t.Fatal(err)
	}
	if checksumCount != 21 {
		t.Fatalf("unexpected PostgreSQL migration checksum count: %d", checksumCount)
	}
}

func TestPostgresUpgradePreservesExistingGenericRepository(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	fixture, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Error(err)
		}
	})
	cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDatabase(t, db))
	path := "sql/sqlite/000001_installation.sql"
	first, err := fs.ReadFile(embeddedMigrations, path)
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, path, string(first)).(fstest.MapFS)
	delete(old, "sql/sqlite/000017_go_modules.sql")
	delete(old, "sql/postgres/000017_go_modules.sql")
	delete(old, "sql/sqlite/000018_cargo_repository_format.sql")
	delete(old, "sql/postgres/000018_cargo_repository_format.sql")
	delete(old, "sql/sqlite/000019_cargo_catalog.sql")
	delete(old, "sql/postgres/000019_cargo_catalog.sql")
	delete(old, "sql/sqlite/000020_cargo_write_tokens.sql")
	delete(old, "sql/postgres/000020_cargo_write_tokens.sql")
	delete(old, "sql/sqlite/000021_cargo_reservations.sql")
	delete(old, "sql/postgres/000021_cargo_reservations.sql")
	report, err := migrateWithFS(ctx, db, cfg, old)
	if err != nil || report.CurrentVersion != 16 {
		t.Fatalf("prepare v16 schema: report=%+v err=%v", report, err)
	}
	userID, workspaceID, repositoryID, versionID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES ($1, 'Synthetic', $2, $3)`, userID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES ($1, 'upgrade', 'Upgrade', $2, $3)`, workspaceID, userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at) VALUES ($1, $2, 'assets', 'Assets', $3, $4, $5)`, repositoryID, workspaceID, userID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_generic_artifact_versions (artifact_version_id, workspace_id, repository_id, collection_name, version_label, status, created_by, created_at, published_at) VALUES ($1, $2, $3, 'fixture', 'v1', 'published', $4, $5, $6)`, versionID, workspaceID, repositoryID, userID, now, now); err != nil {
		t.Fatal(err)
	}
	fileID, digest := uuid.NewString(), strings.Repeat("a", 64)
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_generic_artifact_files (artifact_file_id, artifact_version_id, workspace_id, repository_id, path, content_type, size_bytes, sha256, created_by, created_at) VALUES ($1, $2, $3, $4, 'fixture.bin', 'application/octet-stream', 12, $5, $6, $7)`, fileID, versionID, workspaceID, repositoryID, digest, userID, now); err != nil {
		t.Fatal(err)
	}
	report, err = Migrate(ctx, db, cfg)
	if err != nil || report.CurrentVersion != 21 || len(report.AppliedVersions) != 5 || report.AppliedVersions[0] != 17 || report.AppliedVersions[1] != 18 || report.AppliedVersions[2] != 19 || report.AppliedVersions[3] != 20 || report.AppliedVersions[4] != 21 {
		t.Fatalf("upgrade to v21: report=%+v err=%v", report, err)
	}
	var format, retained, status, publishedAt string
	if err := db.QueryRowContext(ctx, `SELECT r.format, v.artifact_version_id, v.status, v.published_at FROM registry_repositories r JOIN registry_generic_artifact_versions v ON v.repository_id = r.repository_id WHERE r.repository_id = $1`, repositoryID).Scan(&format, &retained, &status, &publishedAt); err != nil || format != "generic" || retained != versionID || status != "published" || publishedAt != now {
		t.Fatalf("upgrade changed existing repository: format=%q version=%q status=%q err=%v", format, retained, status, err)
	}
	var retainedDigest string
	if err := db.QueryRowContext(ctx, `SELECT sha256 FROM registry_generic_artifact_files WHERE artifact_file_id = $1 AND artifact_version_id = $2`, fileID, versionID).Scan(&retainedDigest); err != nil || retainedDigest != digest {
		t.Fatalf("upgrade changed existing file reference: err=%v", err)
	}
}

func TestPostgresV18PreservesGoRepositoryAndGrants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Error(err)
		}
	})
	cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDatabase(t, db))
	first, err := fs.ReadFile(embeddedMigrations, "sql/sqlite/000001_installation.sql")
	if err != nil {
		t.Fatal(err)
	}
	old := migrationFS(t, "sql/sqlite/000001_installation.sql", string(first)).(fstest.MapFS)
	delete(old, "sql/sqlite/000018_cargo_repository_format.sql")
	delete(old, "sql/postgres/000018_cargo_repository_format.sql")
	delete(old, "sql/sqlite/000019_cargo_catalog.sql")
	delete(old, "sql/postgres/000019_cargo_catalog.sql")
	delete(old, "sql/sqlite/000020_cargo_write_tokens.sql")
	delete(old, "sql/postgres/000020_cargo_write_tokens.sql")
	delete(old, "sql/sqlite/000021_cargo_reservations.sql")
	delete(old, "sql/postgres/000021_cargo_reservations.sql")
	if report, err := migrateWithFS(ctx, db, cfg, old); err != nil || report.CurrentVersion != 17 {
		t.Fatalf("prepare v17: %+v err=%v", report, err)
	}
	user, workspace, repository, grant := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, item := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES ($1, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES ($1, 'fixture', 'Fixture', $2, 'now')`, []any{workspace, user}},
		{`INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, created_by, created_at, updated_at) VALUES ($1, $2, 'owner', $3, 'now', 'now')`, []any{workspace, user, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES ($1, $2, 'modules', 'Modules', $3, 'now', 'now', 'go')`, []any{repository, workspace, user}},
		{`INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES ($1, $2, $3, $4, 'reader', $5, 'now')`, []any{grant, repository, workspace, user, user}},
		{`INSERT INTO registry_go_private_prefixes (workspace_id, repository_id, prefix) VALUES ($1, $2, 'example.com/private')`, []any{workspace, repository}},
	} {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	report, err := Migrate(ctx, db, cfg)
	if err != nil || report.CurrentVersion != 21 || len(report.AppliedVersions) != 4 || report.AppliedVersions[0] != 18 || report.AppliedVersions[1] != 19 || report.AppliedVersions[2] != 20 || report.AppliedVersions[3] != 21 {
		t.Fatalf("upgrade to v21: %+v err=%v", report, err)
	}
	if err := VerifyCurrent(ctx, db, config.Postgres, report.InstallationID); err != nil {
		t.Fatalf("verify upgraded history: %v", err)
	}
	var grants, prefixes int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_repository_grants WHERE repository_id = $1`, repository).Scan(&grants); err != nil || grants != 1 {
		t.Fatalf("grant not preserved: count=%d err=%v", grants, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_go_private_prefixes WHERE repository_id = $1`, repository).Scan(&prefixes); err != nil || prefixes != 1 {
		t.Fatalf("namespace not preserved: count=%d err=%v", prefixes, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET format = 'generic' WHERE repository_id = $1`, repository); err == nil {
		t.Fatal("existing repository format became mutable")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES ($1, $2, 'cargo', 'Cargo', $3, 'now', 'now', 'cargo')`, uuid.NewString(), workspace, user); err != nil {
		t.Fatalf("v18 schema did not accept Cargo identity: %v", err)
	}
}

func TestPostgresCargoCatalogConstraints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture, err := testinfra.StartPostgres(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Error(err)
		}
	})
	cfg := config.Config{DatabaseDriver: config.Postgres, DatabaseDSN: fixture.DSN(), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeDatabase(t, db))
	if _, err := Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	exerciseCargoCatalogConstraints(t, ctx, db, config.Postgres)
}
