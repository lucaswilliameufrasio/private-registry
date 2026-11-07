package artifacts

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"private-registry/internal/backup"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/repositories"
	"private-registry/internal/sessions"
	"private-registry/internal/spikes/sqlitebackup"
)

func TestIsolatedRecoveryInvalidatesOldCapabilitiesWithoutChangingSource(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	readerID := fixture.userIDs["reader"]
	payload := []byte("synthetic recovery credentials")
	upload := startFixtureUpload(t, fixture, fixture.userIDs["publisher"], "recovery", "v1", "file", payload)
	if _, err := fixture.service.ReceiveUpload(ctx, fixture.userIDs["publisher"], fixture.workspaceID, fixture.repositoryID, upload.ID, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	version, err := fixture.service.Publish(ctx, fixture.userIDs["publisher"], fixture.workspaceID, fixture.repositoryID, upload.ArtifactVersionID)
	if err != nil || len(version.Files) != 1 {
		t.Fatalf("publish synthetic artifact: %v", err)
	}
	sourceSessions, err := sessions.New(fixture.db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	session, err := sourceSessions.Create(ctx, readerID, sessions.LevelStandard)
	if err != nil {
		t.Fatal(err)
	}
	personal, err := fixture.service.repositories.IssuePersonalReadToken(ctx, readerID, fixture.workspaceID, fixture.repositoryID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := fixture.service.IssueDownloadTicket(ctx, readerID, fixture.workspaceID, fixture.repositoryID, version.ID, version.Files[0].ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "recovery")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "registry.sqlite")
	if _, err := sqlitebackup.Snapshot(ctx, fixture.db, path, sqlitebackup.Options{PagesPerStep: 16}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: root, DatabaseDriver: config.SQLite, DatabaseDSN: path, DatabaseMaxOpenConns: 2}
	recoveredDB, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recoveredDB.Close() })
	failedTx, err := recoveredDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failedTx.ExecContext(ctx, `CREATE TRIGGER synthetic_recovery_audit_failure BEFORE INSERT ON registry_audit_events BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
		_ = failedTx.Rollback()
		t.Fatal(err)
	}
	if _, err := backup.InvalidateRestoredCredentials(ctx, failedTx, config.SQLite, time.Now()); err == nil {
		_ = failedTx.Rollback()
		t.Fatal("recovery accepted a failed audit write")
	}
	if err := failedTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var unrevoked int
	if err := recoveredDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_auth_sessions WHERE revoked_at IS NULL`).Scan(&unrevoked); err != nil || unrevoked != 1 {
		t.Fatalf("rollback did not preserve recovered session count=%d error=%v", unrevoked, err)
	}
	tx, err := recoveredDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	counts, err := backup.InvalidateRestoredCredentials(ctx, tx, config.SQLite, time.Now())
	if err != nil || counts.Sessions != 1 || counts.PersonalTokens != 1 || counts.DownloadTickets != 1 {
		_ = tx.Rollback()
		t.Fatalf("isolated invalidation counts=%+v error=%v", counts, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	recoveredSessions, err := sessions.New(recoveredDB, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recoveredSessions.Validate(ctx, session.BearerToken); !errors.Is(err, sessions.ErrSessionUnavailable) {
		t.Fatalf("recovered old session accepted: %v", err)
	}
	recoveredRepositories, err := repositories.New(recoveredDB, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recoveredRepositories.VerifyPersonalReadToken(ctx, personal.Bearer, fixture.workspaceID, fixture.repositoryID); !errors.Is(err, repositories.ErrPersonalTokenUnavailable) {
		t.Fatalf("recovered old personal token accepted: %v", err)
	}
	recoveredArtifacts, err := New(recoveredDB, config.SQLite, recoveredRepositories, fixture.storage, Options{MaxUploadBytes: 1024, MaxConcurrentUploads: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := recoveredArtifacts.ResolveDownloadTicket(ctx, ticket.Token); !errors.Is(err, ErrDownloadTicketUnavailable) {
		t.Fatalf("recovered old download ticket accepted: %v", err)
	}
	if _, err := sourceSessions.Validate(ctx, session.BearerToken); err != nil {
		t.Fatal("source session changed by isolated recovery:", err)
	}
	if _, err := fixture.service.repositories.VerifyPersonalReadToken(ctx, personal.Bearer, fixture.workspaceID, fixture.repositoryID); err != nil {
		t.Fatal("source token changed by isolated recovery:", err)
	}
	if _, _, err := fixture.service.ResolveDownloadTicket(ctx, ticket.Token); err != nil {
		t.Fatal("source ticket changed by isolated recovery:", err)
	}
	var auditCount int
	if err := recoveredDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_audit_events WHERE action = 'recovery.credentials.invalidated' AND actor_type = 'operator'`).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("recovery audit count=%d error=%v", auditCount, err)
	}
	futureTx, err := recoveredDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := futureTx.ExecContext(ctx, `INSERT INTO registry_migration_checksums (version_id, checksum) VALUES (16, ?)`, "0000000000000000000000000000000000000000000000000000000000000000"); err != nil {
		_ = futureTx.Rollback()
		t.Fatal(err)
	}
	if _, err := backup.InvalidateRestoredCredentials(ctx, futureTx, config.SQLite, time.Now()); err == nil {
		_ = futureTx.Rollback()
		t.Fatal("unknown future credential schema was accepted")
	}
	if err := futureTx.Rollback(); err != nil {
		t.Fatal(err)
	}
}
