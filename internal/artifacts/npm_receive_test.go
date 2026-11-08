package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/npm"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

type revokeNPMReader struct {
	reader io.Reader
	revoke func() error
}

type corruptNPMReadback struct{ storage.Driver }

func (s corruptNPMReadback) Open(ctx context.Context, key storage.ObjectKey) (io.ReadCloser, storage.ObjectInfo, error) {
	reader, info, err := s.Driver.Open(ctx, key)
	if err != nil {
		return reader, info, err
	}
	if err := reader.Close(); err != nil {
		return nil, storage.ObjectInfo{}, err
	}
	return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), int(info.Size)))), info, nil
}

type blockingNPMReader struct {
	reader  io.Reader
	entered chan struct{}
	release chan struct{}
	ctx     context.Context
}

func (r *blockingNPMReader) Read(p []byte) (int, error) {
	if r.entered != nil {
		close(r.entered)
		r.entered = nil
		select {
		case <-r.release:
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		}
	}
	return r.reader.Read(p)
}

func (r *revokeNPMReader) Read(p []byte) (int, error) {
	if r.revoke != nil {
		revoke := r.revoke
		r.revoke = nil
		if err := revoke(); err != nil {
			return 0, err
		}
	}
	return r.reader.Read(p)
}

func TestSQLiteNPMReceiptValidatesAndStores(t *testing.T) {
	fixture := newArtifactFixture(t)
	exerciseNPMReceiptValidatesAndStores(t, fixture.db, config.SQLite, fixture.repositoryService, fixture.storage, fixture.workspaceID, fixture.userIDs["owner"], fixture.userIDs["publisher"])
}

func exerciseNPMReceiptValidatesAndStores(t *testing.T, db *sql.DB, driver config.DatabaseDriver, repos *repositories.Service, objects storage.Driver, workspace, owner, publisher string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p := func(n int) string {
		if driver == config.Postgres {
			return fmt.Sprintf("$%d", n)
		}
		return "?"
	}
	repository := uuid.NewString()
	query := `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format, review_required) VALUES (` + p(1) + `, ` + p(2) + `, 'npm-receive', 'npm', ` + p(3) + `, 'now', 'now', 'npm', 1)`
	if _, err := db.ExecContext(ctx, query, repository, workspace, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, repository, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	token, err := repos.IssueNPMWriteToken(ctx, publisher, workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"name":"fixture","version":"1.0.0"}`)
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	if err := archive.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	content := buffer.Bytes()
	digest, metadata, integrity := sha256.Sum256(content), sha256.Sum256(manifest), sha512.Sum512(content)
	request := npm.ReservationRequest{Name: "fixture", Version: "1.0.0", TarballSHA256: hex.EncodeToString(digest[:]), TarballSize: int64(len(content)), MetadataSHA256: hex.EncodeToString(metadata[:])}
	reservations, err := npm.NewReservationService(db, repos, driver)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(t.TempDir(), "staging")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	limits := npm.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}
	receiver, err := npm.NewReceiptService(db, repos, driver, objects, npm.ReceiptOptions{StagingDirectory: stage, Limits: limits, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	publication := npm.PublishDocument{Name: request.Name, Version: request.Version, Manifest: manifest, Size: int64(len(content)), Integrity: "sha512-" + base64.StdEncoding.EncodeToString(integrity[:])}
	bad := bytes.Clone(content)
	bad[len(bad)-1] ^= 1
	if err := receiver.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, publication, bytes.NewReader(bad)); err == nil {
		t.Fatal("tampered npm tarball was accepted")
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM registry_npm_reservations WHERE reservation_id = `+p(1), reservation.ID).Scan(&status); err != nil || status != "reserved" {
		t.Fatalf("failed receipt did not release claim: status=%q err=%v", status, err)
	}
	corruptReceiver, err := npm.NewReceiptService(db, repos, driver, corruptNPMReadback{Driver: objects}, npm.ReceiptOptions{StagingDirectory: stage, Limits: limits, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := corruptReceiver.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, publication, bytes.NewReader(content)); err == nil {
		t.Fatal("npm receipt accepted corrupted object readback")
	}
	var readbackVerified int
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_npm_reservations WHERE reservation_id = `+p(1), reservation.ID).Scan(&status, &readbackVerified); err != nil || status != "reserved" || readbackVerified != 0 {
		t.Fatalf("corrupt readback left a verified receipt: status=%q verified=%d err=%v", status, readbackVerified, err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_npm_receipt_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'npm.receipt.verified' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if err := receiver.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, publication, bytes.NewReader(content)); err == nil {
			t.Fatal("npm receipt succeeded without audit")
		}
		var verified int
		if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_npm_reservations WHERE reservation_id = ?`, reservation.ID).Scan(&status, &verified); err != nil || status != "reserved" || verified != 0 {
			t.Fatalf("failed receipt audit left verified state: status=%q verified=%d err=%v", status, verified, err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_npm_receipt_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	blocking := &blockingNPMReader{reader: bytes.NewReader(content), entered: make(chan struct{}), release: make(chan struct{}), ctx: ctx}
	entered := blocking.entered
	result := make(chan error, 1)
	go func() {
		result <- receiver.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, publication, blocking)
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("npm receipt did not begin reading")
	}
	if err := receiver.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, publication, bytes.NewReader(content)); !errors.Is(err, npm.ErrReceiptCapacity) {
		close(blocking.release)
		<-result
		t.Fatalf("npm receipt capacity limit was not enforced: %v", err)
	}
	secondReceiver, err := npm.NewReceiptService(db, repos, driver, objects, npm.ReceiptOptions{StagingDirectory: stage, Limits: limits, MaxConcurrent: 1})
	if err != nil {
		close(blocking.release)
		<-result
		t.Fatal(err)
	}
	if err := secondReceiver.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, publication, bytes.NewReader(content)); !errors.Is(err, npm.ErrReservationUnavailable) {
		close(blocking.release)
		<-result
		t.Fatalf("another receiver claimed an active npm upload: %v", err)
	}
	close(blocking.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	var verified, hold int
	var storedManifest, storedIntegrity string
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified, review_hold, manifest, integrity FROM registry_npm_reservations WHERE reservation_id = `+p(1), reservation.ID).Scan(&status, &verified, &hold, &storedManifest, &storedIntegrity); err != nil || status != "uploaded" || verified != 1 || hold != 1 || storedManifest != string(manifest) || storedIntegrity != publication.Integrity {
		t.Fatalf("npm receipt not recorded correctly: status=%q verified=%d hold=%d err=%v", status, verified, hold, err)
	}
	if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
		t.Fatalf("npm receipt staging not cleaned: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_npm_reservations SET manifest = '{}' WHERE reservation_id = `+p(1), reservation.ID); err == nil {
		t.Fatal("verified npm receipt was mutable")
	}
	if _, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, npm.ReservationRequest{Name: request.Name, Version: "1.0.0+other", TarballSHA256: strings.Repeat("a", 64), TarballSize: request.TarballSize, MetadataSHA256: request.MetadataSHA256}); err == nil {
		t.Fatal("conflicting uploaded npm identity was accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET logical_quota_bytes = `+p(1)+` WHERE repository_id = `+p(2), request.TarballSize, repository); err != nil {
		t.Fatal(err)
	}
	overQuota := request
	overQuota.Name = "other"
	overQuota.TarballSize = 1
	if _, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, overQuota); !errors.Is(err, npm.ErrReservationQuota) {
		t.Fatalf("uploaded npm receipt was not counted towards repository quota: %v", err)
	}
	secondRepository := uuid.NewString()
	query = `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'npm-revoke-receive', 'npm', ` + p(3) + `, 'now', 'now', 'npm')`
	if _, err := db.ExecContext(ctx, query, secondRepository, workspace, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, secondRepository, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	secondToken, err := repos.IssueNPMWriteToken(ctx, publisher, workspace, secondRepository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	secondReservation, err := reservations.Reserve(ctx, secondToken.Bearer, workspace, secondRepository, request)
	if err != nil {
		t.Fatal(err)
	}
	reader := &revokeNPMReader{reader: bytes.NewReader(content), revoke: func() error {
		return repos.RevokeRepositoryRole(ctx, owner, workspace, secondRepository, publisher, repositories.GrantPublisher)
	}}
	if err := receiver.Receive(ctx, secondToken.Bearer, workspace, secondRepository, secondReservation.ID, publication, reader); err == nil {
		t.Fatal("npm receipt succeeded after publisher grant revocation")
	}
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_npm_reservations WHERE reservation_id = `+p(1), secondReservation.ID).Scan(&status, &verified); err != nil || status != "reserved" || verified != 0 {
		t.Fatalf("revoked publisher left a verified receipt: status=%q verified=%d err=%v", status, verified, err)
	}
	if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
		t.Fatalf("revoked npm receipt left staging: %v", err)
	}
}
