package artifacts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/backup"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/repositories"
	"private-registry/internal/spikes/sqlitebackup"
)

func TestPartialRecoveryRejectsCargoVersionsWithoutChangingSource(t *testing.T) {
	for _, kind := range []string{"version", "receipt"} {
		t.Run(kind, func(t *testing.T) {
			exercisePartialRecoveryRejectsCargo(t, kind)
		})
	}
}

func exercisePartialRecoveryRejectsCargo(t *testing.T, kind string) {
	t.Helper()
	fixture := newArtifactFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	user := fixture.userIDs["publisher"]
	repository, packageID, versionID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'synthetic-cargo', 'Synthetic Cargo', ?, 'now', 'now', 'cargo')`, repository, fixture.workspaceID, user); err != nil {
		t.Fatal(err)
	}
	if kind == "version" {
		for _, item := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO registry_cargo_packages (package_id, workspace_id, repository_id, name, name_identity, created_by, created_at) VALUES (?, ?, ?, 'fixture', 'fixture', ?, 'now')`, []any{packageID, fixture.workspaceID, repository, user}},
			{`INSERT INTO registry_cargo_versions (cargo_version_id, workspace_id, repository_id, package_id, version, version_identity, index_entry, archive_sha256, archive_size, created_by, created_at) VALUES (?, ?, ?, ?, '1.0.0', '1.0.0', '{}', ?, 12, ?, 'now')`, []any{versionID, fixture.workspaceID, repository, packageID, strings.Repeat("a", 64), user}},
		} {
			if _, err := fixture.db.ExecContext(ctx, item.query, item.args...); err != nil {
				t.Fatal(err)
			}
		}
	} else {
		if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, fixture.userIDs["owner"], fixture.workspaceID, repository, user, repositories.GrantPublisher); err != nil {
			t.Fatal(err)
		}
		token, err := fixture.repositoryService.IssueCargoWriteToken(ctx, user, fixture.workspaceID, repository, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		service, err := cargo.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
		if err != nil {
			t.Fatal(err)
		}
		reservation, err := service.Reserve(ctx, token.Bearer, fixture.workspaceID, repository, cargo.PublishFrame{Metadata: []byte(`{"name":"fixture","vers":"1.0.0","deps":[],"features":{}}`), Size: 12, SHA256: strings.Repeat("a", 64)})
		if err != nil {
			t.Fatal(err)
		}
		versionID = reservation.ID
		if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET status = 'uploading', upload_claim_id = ? WHERE reservation_id = ?`, uuid.NewString(), versionID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET status = 'uploaded', upload_claim_id = NULL, object_verified = 1, index_entry = '{}' WHERE reservation_id = ?`, versionID); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	snapshotPath := filepath.Join(root, "snapshot.sqlite")
	if _, err := sqlitebackup.Snapshot(ctx, fixture.db, snapshotPath, sqlitebackup.Options{PagesPerStep: 16}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	var installationID string
	if err := fixture.db.QueryRowContext(ctx, `SELECT installation_id FROM registry_installation WHERE singleton_id = 1`).Scan(&installationID); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	backupID := uuid.NewString()
	set := backup.GenericSet{Version: 1, InstallationID: installationID, BackupID: backupID, SnapshotSHA256: hex.EncodeToString(digest[:]), Objects: []backup.ObjectReceipt{}}
	envelope, err := backup.SignGenericSet(set, private)
	if err != nil {
		t.Fatal(err)
	}
	trusted := backup.GenericSetRecovery{Signer: public, InstallationID: installationID, BackupID: backupID, SnapshotSHA256: set.SnapshotSHA256}
	parent := filepath.Join(root, "recovery-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.PrepareSQLiteRecovery(ctx, bytes.NewReader(snapshot), 64<<20, 10, 10, envelope, trusted, parent, "incomplete"); err == nil || !strings.Contains(err.Error(), "Cargo") {
		t.Fatalf("partial recovery did not reject Cargo versions: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "incomplete", "RECOVERY_INCOMPLETE")); err != nil {
		t.Fatal("failed recovery marker missing:", err)
	}
	var count int
	query := `SELECT count(*) FROM registry_cargo_versions WHERE cargo_version_id = ? AND archive_sha256 = ?`
	if kind == "receipt" {
		query = `SELECT count(*) FROM registry_cargo_reservations WHERE reservation_id = ? AND archive_sha256 = ? AND status = 'uploaded' AND object_verified = 1`
	}
	if err := fixture.db.QueryRowContext(ctx, query, versionID, strings.Repeat("a", 64)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("source Cargo version changed: count=%d err=%v", count, err)
	}
}
