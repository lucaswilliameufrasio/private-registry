package artifacts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/backup"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/jobs"
	"private-registry/internal/migrations"
	"private-registry/internal/npm"
	"private-registry/internal/repositories"
	"private-registry/internal/sessions"
	"private-registry/internal/spikes/sqlitebackup"
)

func TestIsolatedRecoveryInvalidatesOldCapabilitiesWithoutChangingSource(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	readerID := fixture.userIDs["reader"]
	var expectedInstallationID string
	if err := fixture.db.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&expectedInstallationID); err != nil {
		t.Fatal(err)
	}
	payload := []byte("synthetic recovery credentials")
	upload := startFixtureUpload(t, fixture, fixture.userIDs["publisher"], "recovery", "v1", "file", payload)
	if _, err := fixture.service.ReceiveUpload(ctx, fixture.userIDs["publisher"], fixture.workspaceID, fixture.repositoryID, upload.ID, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	version, err := fixture.service.Publish(ctx, fixture.userIDs["publisher"], fixture.workspaceID, fixture.repositoryID, upload.ArtifactVersionID)
	if err != nil || len(version.Files) != 1 {
		t.Fatalf("publish synthetic artifact: %v", err)
	}
	publisherID := fixture.userIDs["publisher"]
	cargoRepository := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'recovery-cargo', 'Recovery Cargo', ?, 'now', 'now', 'cargo')`, cargoRepository, fixture.workspaceID, fixture.userIDs["owner"]); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, fixture.userIDs["owner"], fixture.workspaceID, cargoRepository, publisherID, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	cargoToken, err := fixture.repositoryService.IssueCargoWriteToken(ctx, publisherID, fixture.workspaceID, cargoRepository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	npmRepository := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'recovery-npm', 'Recovery npm', ?, 'now', 'now', 'npm')`, npmRepository, fixture.workspaceID, fixture.userIDs["owner"]); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, fixture.userIDs["owner"], fixture.workspaceID, npmRepository, publisherID, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	npmToken, err := fixture.repositoryService.IssueNPMWriteToken(ctx, publisherID, fixture.workspaceID, npmRepository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	npmReservations, err := npm.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	npmReservation, err := npmReservations.Reserve(ctx, npmToken.Bearer, fixture.workspaceID, npmRepository, npm.ReservationRequest{Name: "fixture", Version: "1.0.0", TarballSHA256: strings.Repeat("b", 64), TarballSize: 7, MetadataSHA256: strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	cargoReservations, err := cargo.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	cargoReservation, err := cargoReservations.Reserve(ctx, cargoToken.Bearer, fixture.workspaceID, cargoRepository, cargo.PublishFrame{Metadata: []byte(`{"name":"fixture","vers":"1.0.0","deps":[],"features":{}}`), Size: 7, SHA256: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	receivingUpload := startFixtureUpload(t, fixture, publisherID, "recovery-receiving", "v1", "file", payload)
	uploadingUpload := startFixtureUpload(t, fixture, publisherID, "recovery-uploading", "v1", "file", payload)
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_generic_upload_sessions SET status = 'uploading', upload_claim_id = ? WHERE upload_session_id = ?`, uuid.NewString(), uploadingUpload.ID); err != nil {
		t.Fatal(err)
	}
	uploadedUpload := startFixtureUpload(t, fixture, publisherID, "recovery-uploaded", "v1", "file", payload)
	if _, err := fixture.service.ReceiveUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID, uploadedUpload.ID, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
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
	jobQueue, err := jobs.New(fixture.db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	jobNow := time.Now().UTC()
	if _, err := jobQueue.Enqueue(ctx, "synthetic-running", "synthetic-recovery", "{}", 3, jobNow, jobNow); err != nil {
		t.Fatal(err)
	}
	activeJob, err := jobQueue.Claim(ctx, "synthetic-recovery", jobNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jobQueue.Enqueue(ctx, "synthetic-pending", "synthetic-recovery", "{}", 3, jobNow, jobNow); err != nil {
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
	snapshotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshotDigest := sha256.Sum256(snapshotBytes)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	backupID := uuid.NewString()
	object := version.Files[0]
	syntheticCipher := sha256.Sum256([]byte("synthetic ciphertext identity"))
	receipt := backup.ObjectReceipt{Version: 1, InstallationID: expectedInstallationID, BackupID: backupID, WorkspaceID: fixture.workspaceID, PlainSHA256: object.SHA256, PlainBytes: object.Size, CipherSHA256: hex.EncodeToString(syntheticCipher[:]), CipherBytes: 1}
	set := backup.GenericSet{Version: 1, InstallationID: expectedInstallationID, BackupID: backupID, SnapshotSHA256: hex.EncodeToString(snapshotDigest[:]), Objects: []backup.ObjectReceipt{receipt}}
	setEnvelope, err := backup.SignGenericSet(set, private)
	if err != nil {
		t.Fatal(err)
	}
	trusted := backup.GenericSetRecovery{Signer: public, InstallationID: expectedInstallationID, BackupID: backupID, SnapshotSHA256: set.SnapshotSHA256}
	parent := filepath.Join(t.TempDir(), "private-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	prepared, err := backup.PrepareSQLiteRecovery(ctx, bytes.NewReader(snapshotBytes), 64<<20, 10, 10, setEnvelope, trusted, parent, "prepared")
	if err != nil || prepared.GenericObjects != 1 || prepared.Invalidated.Sessions != 1 || prepared.Invalidated.PersonalTokens != 1 || prepared.Invalidated.CargoWriteTokens != 1 || prepared.Invalidated.NPMWriteTokens != 1 || prepared.Invalidated.DownloadTickets != 1 || prepared.HeldJobs != 2 || prepared.InvalidatedUploads != 5 {
		t.Fatalf("prepare isolated SQLite recovery: %+v error=%v", prepared, err)
	}
	if _, err := os.Stat(filepath.Join(parent, "prepared", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal("recovery incomplete marker missing:", err)
	}
	beforeRetry, err := os.ReadFile(prepared.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.PrepareSQLiteRecovery(ctx, bytes.NewReader(snapshotBytes), 64<<20, 10, 10, setEnvelope, trusted, parent, "prepared"); err == nil {
		t.Fatal("existing recovery destination was overwritten")
	}
	afterRetry, err := os.ReadFile(prepared.DatabasePath)
	if err != nil || !bytes.Equal(beforeRetry, afterRetry) {
		t.Fatalf("existing recovery destination changed on retry: %v", err)
	}
	corrupt := bytes.Clone(snapshotBytes)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := backup.PrepareSQLiteRecovery(ctx, bytes.NewReader(corrupt), 64<<20, 10, 10, setEnvelope, trusted, parent, "corrupt"); err == nil {
		t.Fatal("snapshot with incorrect signed digest was accepted")
	}
	if _, err := os.Stat(filepath.Join(parent, "corrupt", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal("failed recovery marker missing:", err)
	}
	preparedCfg := config.Config{DataDir: filepath.Join(parent, "prepared"), DatabaseDriver: config.SQLite, DatabaseDSN: prepared.DatabasePath, DatabaseMaxOpenConns: 2}
	preparedDB, err := database.Open(ctx, preparedCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = preparedDB.Close() })
	var recoveredStatus, sourceStatus string
	var recoveredInvalidated, sourceInvalidated int
	if err := preparedDB.QueryRowContext(ctx, `SELECT status, recovery_invalidated FROM registry_cargo_reservations WHERE reservation_id = ?`, cargoReservation.ID).Scan(&recoveredStatus, &recoveredInvalidated); err != nil || recoveredStatus != "expired" || recoveredInvalidated != 1 {
		t.Fatalf("recovered Cargo reservation not invalidated: %v", err)
	}
	if err := fixture.db.QueryRowContext(ctx, `SELECT status, recovery_invalidated FROM registry_cargo_reservations WHERE reservation_id = ?`, cargoReservation.ID).Scan(&sourceStatus, &sourceInvalidated); err != nil || sourceStatus != "reserved" || sourceInvalidated != 0 {
		t.Fatalf("source Cargo reservation changed: %v", err)
	}
	preparedQueue, err := jobs.New(preparedDB, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preparedQueue.Claim(ctx, "synthetic-recovery", jobNow.Add(2*time.Hour), time.Minute); !errors.Is(err, jobs.ErrNoJob) {
		t.Fatalf("held recovery job could be claimed: %v", err)
	}
	if err := preparedQueue.Finish(ctx, activeJob.ID, activeJob.LeaseToken, true, jobNow.Add(time.Second), time.Time{}); !errors.Is(err, jobs.ErrLease) {
		t.Fatalf("restored lease remained valid: %v", err)
	}
	var heldRunning, heldPending int
	if err := preparedDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_jobs WHERE recovery_previous_status = 'running' AND lease_token IS NULL AND lease_until_ms IS NULL`).Scan(&heldRunning); err != nil || heldRunning != 1 {
		t.Fatalf("running recovery hold count=%d err=%v", heldRunning, err)
	}
	if err := preparedDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_jobs WHERE recovery_previous_status = 'pending'`).Scan(&heldPending); err != nil || heldPending != 1 {
		t.Fatalf("pending recovery hold count=%d err=%v", heldPending, err)
	}
	if err := jobQueue.Heartbeat(ctx, activeJob.ID, activeJob.LeaseToken, jobNow.Add(time.Second), time.Hour); err != nil {
		t.Fatal("source job changed during isolated recovery:", err)
	}
	preparedSessions, err := sessions.New(preparedDB, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preparedSessions.Validate(ctx, session.BearerToken); !errors.Is(err, sessions.ErrSessionUnavailable) {
		t.Fatalf("prepared old session accepted: %v", err)
	}
	preparedRepositories, err := repositories.New(preparedDB, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preparedRepositories.VerifyPersonalReadToken(ctx, personal.Bearer, fixture.workspaceID, fixture.repositoryID); !errors.Is(err, repositories.ErrPersonalTokenUnavailable) {
		t.Fatalf("prepared old token accepted: %v", err)
	}
	preparedArtifacts, err := New(preparedDB, config.SQLite, preparedRepositories, fixture.storage, Options{MaxUploadBytes: 1024, MaxConcurrentUploads: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := preparedArtifacts.ResolveDownloadTicket(ctx, ticket.Token); !errors.Is(err, ErrDownloadTicketUnavailable) {
		t.Fatalf("prepared old ticket accepted: %v", err)
	}
	for _, id := range []string{receivingUpload.ID, uploadingUpload.ID} {
		var status string
		var claim sql.NullString
		var invalidated int
		if err := preparedDB.QueryRowContext(ctx, `SELECT status, upload_claim_id, recovery_invalidated FROM registry_generic_upload_sessions WHERE upload_session_id = ?`, id).Scan(&status, &claim, &invalidated); err != nil || status != "expired" || claim.Valid || invalidated != 1 {
			t.Fatalf("prepared upload state=%s claim=%v invalidated=%d err=%v", status, claim.Valid, invalidated, err)
		}
	}
	if _, err := preparedArtifacts.Publish(ctx, publisherID, fixture.workspaceID, fixture.repositoryID, uploadedUpload.ArtifactVersionID); !errors.Is(err, ErrVersionIncomplete) {
		t.Fatalf("invalidated uploaded receipt could be published: %v", err)
	}
	var objectDigest string
	var invalidated int
	if err := preparedDB.QueryRowContext(ctx, `SELECT object_sha256, recovery_invalidated FROM registry_generic_upload_sessions WHERE upload_session_id = ?`, uploadedUpload.ID).Scan(&objectDigest, &invalidated); err != nil || objectDigest != object.SHA256 || invalidated != 1 {
		t.Fatalf("uploaded recovery reference changed: invalidated=%d err=%v", invalidated, err)
	}
	if _, err := fixture.service.Publish(ctx, publisherID, fixture.workspaceID, fixture.repositoryID, uploadedUpload.ArtifactVersionID); err != nil {
		t.Fatal("source uploaded receipt changed during isolated recovery:", err)
	}
	wrongSet := set
	wrongSet.Objects = []backup.ObjectReceipt{}
	wrongEnvelope, err := backup.SignGenericSet(wrongSet, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.PrepareSQLiteRecovery(ctx, bytes.NewReader(snapshotBytes), 64<<20, 10, 10, wrongEnvelope, trusted, parent, "missing-object"); err == nil {
		t.Fatal("signed set missing snapshot object was accepted")
	}
	if _, err := os.Stat(filepath.Join(parent, "missing-object", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal("incomplete recovery marker missing:", err)
	}
	cfg := config.Config{DataDir: root, DatabaseDriver: config.SQLite, DatabaseDSN: path, DatabaseMaxOpenConns: 2}
	recoveredDB, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recoveredDB.Close() })
	if err := backup.VerifySQLiteIntegrity(ctx, recoveredDB); err != nil {
		t.Fatal("verify isolated recovered SQLite integrity:", err)
	}
	if err := migrations.VerifyCurrent(ctx, recoveredDB, config.SQLite, expectedInstallationID); err != nil {
		t.Fatal("verify isolated recovery schema:", err)
	}
	rollbackTx, err := recoveredDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rollbackTx.ExecContext(ctx, `CREATE TRIGGER synthetic_upload_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'recovery.uploads.invalidated' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
		_ = rollbackTx.Rollback()
		t.Fatal(err)
	}
	if _, err := backup.HoldRestoredJobs(ctx, rollbackTx, config.SQLite, jobNow); err != nil {
		_ = rollbackTx.Rollback()
		t.Fatal(err)
	}
	if _, err := backup.InvalidateRestoredUploads(ctx, rollbackTx, config.SQLite, jobNow); err == nil {
		_ = rollbackTx.Rollback()
		t.Fatal("upload recovery accepted a failed audit write")
	}
	if err := rollbackTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var unchangedStatus string
	var unchangedInvalidation int
	if err := recoveredDB.QueryRowContext(ctx, `SELECT status, recovery_invalidated FROM registry_generic_upload_sessions WHERE upload_session_id = ?`, receivingUpload.ID).Scan(&unchangedStatus, &unchangedInvalidation); err != nil || unchangedStatus != "receiving" || unchangedInvalidation != 0 {
		t.Fatalf("recovery rollback changed upload: status=%s invalidated=%d err=%v", unchangedStatus, unchangedInvalidation, err)
	}
	var runningStatus string
	var held sql.NullString
	if err := recoveredDB.QueryRowContext(ctx, `SELECT status, recovery_previous_status FROM registry_jobs WHERE job_id = ?`, activeJob.ID).Scan(&runningStatus, &held); err != nil || runningStatus != "running" || held.Valid {
		t.Fatalf("recovery rollback changed job: status=%s held=%v err=%v", runningStatus, held.Valid, err)
	}
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
	applyCargo := func(_ *sql.Tx, _ string) error { return nil }
	if err := recoveredRepositories.WithCargoWriteTokenTransaction(ctx, cargoToken.Bearer, fixture.workspaceID, cargoRepository, applyCargo); !errors.Is(err, repositories.ErrCargoWriteTokenUnavailable) {
		t.Fatalf("recovered Cargo credential accepted: %v", err)
	}
	if err := fixture.repositoryService.WithCargoWriteTokenTransaction(ctx, cargoToken.Bearer, fixture.workspaceID, cargoRepository, applyCargo); err != nil {
		t.Fatalf("source Cargo credential changed by isolated recovery: %v", err)
	}
	if err := recoveredRepositories.WithNPMWriteTokenTransaction(ctx, npmToken.Bearer, fixture.workspaceID, npmRepository, applyCargo); !errors.Is(err, repositories.ErrNPMWriteTokenUnavailable) {
		t.Fatalf("recovered npm credential accepted: %v", err)
	}
	if err := fixture.repositoryService.WithNPMWriteTokenTransaction(ctx, npmToken.Bearer, fixture.workspaceID, npmRepository, applyCargo); err != nil {
		t.Fatalf("source npm credential changed by isolated recovery: %v", err)
	}
	var npmStatus string
	var npmInvalidated int
	if err := preparedDB.QueryRowContext(ctx, `SELECT status, recovery_invalidated FROM registry_npm_reservations WHERE reservation_id = ?`, npmReservation.ID).Scan(&npmStatus, &npmInvalidated); err != nil || npmStatus != "expired" || npmInvalidated != 1 {
		t.Fatalf("recovered npm reservation was not invalidated: status=%q invalidated=%d err=%v", npmStatus, npmInvalidated, err)
	}
	if err := fixture.db.QueryRowContext(ctx, `SELECT status, recovery_invalidated FROM registry_npm_reservations WHERE reservation_id = ?`, npmReservation.ID).Scan(&npmStatus, &npmInvalidated); err != nil || npmStatus != "reserved" || npmInvalidated != 0 {
		t.Fatalf("source npm reservation changed: status=%q invalidated=%d err=%v", npmStatus, npmInvalidated, err)
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
	if _, err := futureTx.ExecContext(ctx, `INSERT INTO registry_migration_checksums (version_id, checksum) VALUES (33, ?)`, "0000000000000000000000000000000000000000000000000000000000000000"); err != nil {
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
	conn, err := recoveredDB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	for _, query := range []string{
		`CREATE TABLE synthetic_parent (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE synthetic_child (parent_id INTEGER REFERENCES synthetic_parent(id))`,
		`INSERT INTO synthetic_child (parent_id) VALUES (42)`,
	} {
		if _, err := conn.ExecContext(ctx, query); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := backup.VerifySQLiteIntegrity(ctx, recoveredDB); err == nil {
		t.Fatal("recovered database with broken foreign key was accepted")
	}
	if _, err := sourceSessions.Validate(ctx, session.BearerToken); err != nil {
		t.Fatal("source session changed after recovered-database failure injection:", err)
	}
}
