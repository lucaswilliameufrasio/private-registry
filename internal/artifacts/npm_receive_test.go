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
	countedObjects := &countingStorage{Driver: objects}
	receiver, err := npm.NewReceiptService(db, repos, driver, countedObjects, npm.ReceiptOptions{StagingDirectory: stage, Limits: limits, MaxConcurrent: 1})
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
	if _, err := repos.GrantNPMReviewer(ctx, owner, workspace, repository, publisher); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, publisher, workspace, repository, reservation.ID, "approved", ""); !errors.Is(err, npm.ErrReviewUnavailable) {
		t.Fatalf("npm publisher approved own receipt: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "approved", ""); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("review without explicit grant accepted: %v", err)
	}
	beforeOpen := countedObjects.opens.Load()
	if reader, _, err := receiver.OpenReviewArchive(ctx, owner, workspace, repository, reservation.ID); !errors.Is(err, repositories.ErrForbidden) || reader != nil {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("review archive opened without reviewer grant: %v", err)
	}
	if countedObjects.opens.Load() != beforeOpen {
		t.Fatal("unauthorized review touched storage")
	}
	if _, err := repos.GrantNPMReviewer(ctx, owner, workspace, repository, owner); err != nil {
		t.Fatal(err)
	}
	candidates, more, err := reservations.ListReviewCandidates(ctx, owner, workspace, repository, "", 10)
	if err != nil || more || len(candidates) != 1 || candidates[0].ID != reservation.ID {
		t.Fatalf("npm review candidate listing failed: %v", err)
	}
	reader, size, err := receiver.OpenReviewArchive(ctx, owner, workspace, repository, reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	archived, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || size != int64(len(content)) || !bytes.Equal(archived, content) {
		t.Fatalf("review archive differs: read=%v close=%v", readErr, closeErr)
	}
	checkApproval := func() error {
		return repos.WithNPMWriteTokenTransaction(ctx, token.Bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
			return reservations.RequireCurrentApproval(ctx, tx, workspace, repository, reservation.ID, actor)
		})
	}
	if err := checkApproval(); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("unreviewed npm receipt was approved: %v", err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_npm_review_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'npm.review.approved' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "approved", ""); err == nil {
			t.Fatal("npm review succeeded without audit")
		}
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_npm_review_decisions WHERE reservation_id = ?`, reservation.ID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed audit left npm review decision: count=%d err=%v", count, err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_npm_review_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	decision, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "approved", "")
	if err != nil {
		t.Fatal(err)
	}
	retryDecision, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "approved", "")
	if err != nil || retryDecision != decision {
		t.Fatalf("identical npm approval retry failed: %v", err)
	}
	if err := checkApproval(); err != nil {
		t.Fatalf("valid npm approval rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_npm_review_decisions SET decision = 'rejected' WHERE decision_id = `+p(1), decision); err == nil {
		t.Fatal("npm review decision was mutable")
	}
	if err := repos.RevokeNPMReviewer(ctx, owner, workspace, repository, owner); err != nil {
		t.Fatal(err)
	}
	if err := checkApproval(); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("revoked reviewer approval remained usable: %v", err)
	}
	if _, err := repos.GrantNPMReviewer(ctx, owner, workspace, repository, owner); err != nil {
		t.Fatal(err)
	}
	if err := checkApproval(); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("reviewer regrant revived prior npm approval: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.SetNPMReviewPolicy(ctx, owner, workspace, repository, 0, false); err != nil {
		t.Fatal(err)
	}
	if err := checkApproval(); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("policy change revived stale npm approval: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	if err := checkApproval(); err != nil {
		t.Fatalf("new npm approval for current policy was rejected: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "rejected", " "); !errors.Is(err, npm.ErrReviewUnavailable) {
		t.Fatalf("empty npm rejection reason accepted: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "rejected", "synthetic review rejection"); err != nil {
		t.Fatal(err)
	}
	if err := checkApproval(); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("rejected npm receipt remained approved: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "approved", ""); !errors.Is(err, npm.ErrReviewUnavailable) {
		t.Fatalf("rejected npm receipt was reapproved: %v", err)
	}
	if candidates, _, err := reservations.ListReviewCandidates(ctx, owner, workspace, repository, "", 10); err != nil || len(candidates) != 0 {
		t.Fatalf("rejected npm receipt remained a review candidate: %v", err)
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
	revokingReader := &revokeNPMReader{reader: bytes.NewReader(content), revoke: func() error {
		return repos.RevokeRepositoryRole(ctx, owner, workspace, secondRepository, publisher, repositories.GrantPublisher)
	}}
	if err := receiver.Receive(ctx, secondToken.Bearer, workspace, secondRepository, secondReservation.ID, publication, revokingReader); err == nil {
		t.Fatal("npm receipt succeeded after publisher grant revocation")
	}
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_npm_reservations WHERE reservation_id = `+p(1), secondReservation.ID).Scan(&status, &verified); err != nil || status != "reserved" || verified != 0 {
		t.Fatalf("revoked publisher left a verified receipt: status=%q verified=%d err=%v", status, verified, err)
	}
	if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
		t.Fatalf("revoked npm receipt left staging: %v", err)
	}
	publicationRepo := uuid.NewString()
	query = `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format, review_required) VALUES (` + p(1) + `, ` + p(2) + `, 'npm-publication', 'npm', ` + p(3) + `, 'now', 'now', 'npm', 1)`
	if _, err := db.ExecContext(ctx, query, publicationRepo, workspace, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, publicationRepo, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	publicationToken, err := repos.IssueNPMWriteToken(ctx, publisher, workspace, publicationRepo, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	publicationReservation, err := reservations.Reserve(ctx, publicationToken.Bearer, workspace, publicationRepo, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.Receive(ctx, publicationToken.Bearer, workspace, publicationRepo, publicationReservation.ID, publication, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.PublishReceipt(ctx, publicationToken.Bearer, workspace, publicationRepo, publicationReservation.ID); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("npm publication without review was accepted: %v", err)
	}
	var catalogCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_npm_versions WHERE repository_id = `+p(1), publicationRepo).Scan(&catalogCount); err != nil || catalogCount != 0 {
		t.Fatalf("pending review left npm catalog version: count=%d err=%v", catalogCount, err)
	}
	if _, err := repos.GrantNPMReviewer(ctx, owner, workspace, publicationRepo, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, owner, workspace, publicationRepo, publicationReservation.ID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	initialTags := map[string]string{"initial": request.Version}
	if _, err := reservations.PublishReceiptWithInitialTags(ctx, publicationToken.Bearer, workspace, publicationRepo, publicationReservation.ID, initialTags); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("npm publication created tags without separate grant: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_npm_versions WHERE repository_id = `+p(1), publicationRepo).Scan(&catalogCount); err != nil || catalogCount != 0 {
		t.Fatalf("denied initial tags left published version: count=%d err=%v", catalogCount, err)
	}
	if _, err := repos.GrantNPMTagManager(ctx, owner, workspace, publicationRepo, publisher); err != nil {
		t.Fatal(err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_npm_publication_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'npm.publication.created' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := reservations.PublishReceiptWithInitialTags(ctx, publicationToken.Bearer, workspace, publicationRepo, publicationReservation.ID, initialTags); err == nil {
			t.Fatal("npm publication succeeded without audit")
		}
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_npm_publications WHERE reservation_id = ?`, publicationReservation.ID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed npm publication audit left linkage: count=%d err=%v", count, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_npm_packages WHERE repository_id = ?`, publicationRepo).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed npm publication audit left package: count=%d err=%v", count, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_npm_versions WHERE repository_id = ?`, publicationRepo).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed npm publication audit left version: count=%d err=%v", count, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_npm_dist_tags WHERE repository_id = ?`, publicationRepo).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed npm publication audit left tag: count=%d err=%v", count, err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_npm_publication_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	publicationResults := make(chan struct {
		id  string
		err error
	}, 2)
	for range 2 {
		go func() {
			id, err := reservations.PublishReceiptWithInitialTags(ctx, publicationToken.Bearer, workspace, publicationRepo, publicationReservation.ID, initialTags)
			publicationResults <- struct {
				id  string
				err error
			}{id, err}
		}()
	}
	firstPublication, secondPublication := <-publicationResults, <-publicationResults
	if firstPublication.err != nil || secondPublication.err != nil || firstPublication.id == "" || firstPublication.id != secondPublication.id {
		t.Fatalf("concurrent npm publication retry failed: %v %v", firstPublication.err, secondPublication.err)
	}
	retryReservation, err := reservations.Reserve(ctx, publicationToken.Bearer, workspace, publicationRepo, request)
	if err != nil || retryReservation.ID != publicationReservation.ID {
		t.Fatalf("published npm retry did not recover original reservation: %v", err)
	}
	alternateToken, err := repos.IssueNPMWriteToken(ctx, publisher, workspace, publicationRepo, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.Reserve(ctx, alternateToken.Bearer, workspace, publicationRepo, request); !errors.Is(err, npm.ErrReservationConflict) {
		t.Fatalf("different credential reused npm publication: %v", err)
	}
	changedRequest := request
	changedRequest.TarballSHA256 = strings.Repeat("f", 64)
	if _, err := reservations.Reserve(ctx, publicationToken.Bearer, workspace, publicationRepo, changedRequest); !errors.Is(err, npm.ErrReservationConflict) {
		t.Fatalf("different npm publication content reused receipt: %v", err)
	}
	if err := repos.RevokeNPMTagManager(ctx, owner, workspace, publicationRepo, publisher); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.PublishReceiptWithInitialTags(ctx, publicationToken.Bearer, workspace, publicationRepo, publicationReservation.ID, initialTags); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("revoked tag manager retried npm publication with tags: %v", err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, publicationRepo, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	readToken, err := repos.IssuePersonalReadToken(ctx, owner, workspace, publicationRepo, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	beforeRead := countedObjects.opens.Load()
	if reader, _, err := receiver.OpenPublishedArchiveWithToken(ctx, publicationToken.Bearer, workspace, publicationRepo, request.Name, request.Version); err == nil || reader != nil {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("npm write credential opened published archive: %v", err)
	}
	if countedObjects.opens.Load() != beforeRead {
		t.Fatal("unauthorized published npm read touched storage")
	}
	publishedReader, publishedSize, err := receiver.OpenPublishedArchiveWithToken(ctx, readToken.Bearer, workspace, publicationRepo, request.Name, request.Version)
	if err != nil {
		t.Fatal(err)
	}
	publishedBytes, readErr := io.ReadAll(publishedReader)
	closeErr = publishedReader.Close()
	if readErr != nil || closeErr != nil || publishedSize != int64(len(content)) || !bytes.Equal(publishedBytes, content) {
		t.Fatalf("published npm archive differs: read=%v close=%v", readErr, closeErr)
	}
	beforeRead = countedObjects.opens.Load()
	if reader, _, err := receiver.OpenPublishedArchiveWithToken(ctx, readToken.Bearer, workspace, repository, request.Name, request.Version); err == nil || reader != nil {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("npm read token opened a different repository: %v", err)
	}
	if countedObjects.opens.Load() != beforeRead {
		t.Fatal("cross-repository npm read touched storage")
	}
	if err := repos.RevokeRepositoryRole(ctx, owner, workspace, publicationRepo, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	beforeRead = countedObjects.opens.Load()
	if reader, _, err := receiver.OpenPublishedArchiveWithToken(ctx, readToken.Bearer, workspace, publicationRepo, request.Name, request.Version); err == nil || reader != nil {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("revoked reader opened npm archive: %v", err)
	}
	if countedObjects.opens.Load() != beforeRead {
		t.Fatal("revoked published npm read touched storage")
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, publicationRepo, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if reader, _, err := receiver.OpenPublishedArchiveWithToken(ctx, readToken.Bearer, workspace, publicationRepo, request.Name, request.Version); err == nil || reader != nil {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("reader regrant revived old npm read token: %v", err)
	}
	if countedObjects.opens.Load() != beforeRead {
		t.Fatal("regranted npm read touched storage using old token")
	}
	var publicationAuditCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events WHERE action = 'npm.publication.created' AND target_id = `+p(1), firstPublication.id).Scan(&publicationAuditCount); err != nil || publicationAuditCount != 1 {
		t.Fatalf("concurrent npm publication audit count=%d err=%v", publicationAuditCount, err)
	}
	if _, err := reservations.DecideReview(ctx, owner, workspace, publicationRepo, publicationReservation.ID, "rejected", "late rejection"); !errors.Is(err, npm.ErrReviewUnavailable) {
		t.Fatalf("published npm receipt accepted a review decision: %v", err)
	}
	if candidates, _, err := reservations.ListReviewCandidates(ctx, owner, workspace, publicationRepo, "", 10); err != nil || len(candidates) != 0 {
		t.Fatalf("published npm receipt remained a review candidate: %v", err)
	}
	if _, err := reservations.SetDistTag(ctx, publisher, workspace, publicationRepo, request.Name, "latest", request.Version, 0); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("publisher moved npm tag without separate grant: %v", err)
	}
	if _, err := repos.GrantNPMTagManager(ctx, owner, workspace, publicationRepo, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.SetDistTag(ctx, owner, workspace, publicationRepo, request.Name, "latest", "2.0.0", 0); !errors.Is(err, npm.ErrTagUnavailable) {
		t.Fatalf("npm tag pointed at missing version: %v", err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_npm_tag_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'npm.tag.updated' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := reservations.SetDistTag(ctx, owner, workspace, publicationRepo, request.Name, "latest", request.Version, 0); err == nil {
			t.Fatal("npm tag change succeeded without audit")
		}
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_npm_dist_tags WHERE repository_id = ? AND tag = 'latest'`, publicationRepo).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed tag audit left state: count=%d err=%v", count, err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_npm_tag_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	tagResults := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := reservations.SetDistTag(ctx, owner, workspace, publicationRepo, request.Name, "latest", request.Version, 0)
			tagResults <- err
		}()
	}
	firstTag, secondTag := <-tagResults, <-tagResults
	if !((firstTag == nil && errors.Is(secondTag, npm.ErrTagConflict)) || (secondTag == nil && errors.Is(firstTag, npm.ErrTagConflict))) {
		t.Fatalf("concurrent npm tag changes did not select one winner: %v %v", firstTag, secondTag)
	}
	if revision, err := reservations.SetDistTag(ctx, owner, workspace, publicationRepo, request.Name, "latest", request.Version, 1); err != nil || revision != 2 {
		t.Fatalf("npm tag update failed: revision=%d err=%v", revision, err)
	}
	currentReadToken, err := repos.IssuePersonalReadToken(ctx, owner, workspace, publicationRepo, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	packageData, err := reservations.ReadPublishedPackageWithToken(ctx, currentReadToken.Bearer, workspace, publicationRepo, request.Name)
	if err != nil || packageData.Name != request.Name || len(packageData.Versions) != 1 || packageData.Versions[0].Version != request.Version || !bytes.Equal(packageData.Versions[0].Manifest, manifest) || packageData.Versions[0].Integrity != publication.Integrity || packageData.Tags["latest"] != request.Version {
		t.Fatalf("published npm metadata differs: %+v err=%v", packageData, err)
	}
	if _, err := reservations.ReadPublishedPackageWithToken(ctx, readToken.Bearer, workspace, publicationRepo, request.Name); !errors.Is(err, repositories.ErrPersonalTokenUnavailable) {
		t.Fatalf("old npm reader token accessed metadata after regrant: %v", err)
	}
	if _, err := reservations.ReadPublishedPackageWithToken(ctx, currentReadToken.Bearer, workspace, repository, request.Name); !errors.Is(err, repositories.ErrPersonalTokenUnavailable) {
		t.Fatalf("npm metadata crossed repository boundary: %v", err)
	}
	var tagEvents int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_npm_tag_events WHERE repository_id = `+p(1)+` AND tag = 'latest'`, publicationRepo).Scan(&tagEvents); err != nil || tagEvents != 2 {
		t.Fatalf("npm tag history count=%d err=%v", tagEvents, err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM registry_npm_tag_events WHERE repository_id = `+p(1), publicationRepo); err == nil {
		t.Fatal("npm tag history was deleted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_npm_tag_events SET revision = 3 WHERE repository_id = `+p(1), publicationRepo); err == nil {
		t.Fatal("npm tag history was mutable")
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_npm_tag_remove_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'npm.tag.removed' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := reservations.RemoveDistTag(ctx, owner, workspace, publicationRepo, request.Name, "latest", 2); err == nil {
			t.Fatal("npm tag removal succeeded without audit")
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_npm_tag_remove_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	if revision, err := reservations.RemoveDistTag(ctx, owner, workspace, publicationRepo, request.Name, "latest", 2); err != nil || revision != 3 {
		t.Fatalf("npm tag removal failed: revision=%d err=%v", revision, err)
	}
	state, err := reservations.GetDistTagState(ctx, owner, workspace, publicationRepo, request.Name, "latest")
	if err != nil || state.Revision != 3 || state.Active || state.Version != "" {
		t.Fatalf("npm tag tombstone differs: %+v err=%v", state, err)
	}
	if _, err := reservations.GetDistTagState(ctx, publisher, workspace, publicationRepo, request.Name, "latest"); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("ungranted publisher read npm tag management state: %v", err)
	}
	packageData, err = reservations.ReadPublishedPackageWithToken(ctx, currentReadToken.Bearer, workspace, publicationRepo, request.Name)
	if err != nil || packageData.Tags["latest"] != "" || packageData.Tags["initial"] != request.Version {
		t.Fatalf("removed npm tag remained visible: %+v err=%v", packageData.Tags, err)
	}
	if _, err := reservations.SetDistTag(ctx, owner, workspace, publicationRepo, request.Name, "latest", request.Version, 2); !errors.Is(err, npm.ErrTagConflict) {
		t.Fatalf("stale npm tag update revived removed tag: %v", err)
	}
	if revision, err := reservations.SetDistTag(ctx, owner, workspace, publicationRepo, request.Name, "latest", request.Version, 3); err != nil || revision != 4 {
		t.Fatalf("npm tag recreation failed: revision=%d err=%v", revision, err)
	}
	state, err = reservations.GetDistTagState(ctx, owner, workspace, publicationRepo, request.Name, "latest")
	if err != nil || state.Revision != 4 || !state.Active || state.Version != request.Version {
		t.Fatalf("recreated npm tag state differs: %+v err=%v", state, err)
	}
	if err := repos.RevokeNPMTagManager(ctx, owner, workspace, publicationRepo, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.SetDistTag(ctx, owner, workspace, publicationRepo, request.Name, "latest", request.Version, 4); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("revoked tag manager moved npm tag: %v", err)
	}
	tagUser := uuid.NewString()
	query = `INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (` + p(1) + `, 'Synthetic tag manager', 'now', 'now')`
	if _, err := db.ExecContext(ctx, query, tagUser); err != nil {
		t.Fatal(err)
	}
	query = `INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, status, created_by, created_at, updated_at) VALUES (` + p(1) + `, ` + p(2) + `, 'member', 'active', ` + p(3) + `, 'now', 'now')`
	if _, err := db.ExecContext(ctx, query, workspace, tagUser, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantNPMTagManager(ctx, owner, workspace, publicationRepo, tagUser); err != nil {
		t.Fatal(err)
	}
	query = `UPDATE registry_workspace_memberships SET status = 'suspended', updated_at = 'synthetic-suspension' WHERE workspace_id = ` + p(1) + ` AND user_id = ` + p(2)
	if _, err := db.ExecContext(ctx, query, workspace, tagUser); err != nil {
		t.Fatal(err)
	}
	query = `UPDATE registry_workspace_memberships SET status = 'active', updated_at = 'synthetic-reactivation' WHERE workspace_id = ` + p(1) + ` AND user_id = ` + p(2)
	if _, err := db.ExecContext(ctx, query, workspace, tagUser); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.SetDistTag(ctx, tagUser, workspace, publicationRepo, request.Name, "latest", request.Version, 4); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("reactivated membership revived npm tag grant: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET logical_quota_bytes = `+p(1)+` WHERE repository_id = `+p(2), request.TarballSize+1, publicationRepo); err != nil {
		t.Fatal(err)
	}
	remaining := request
	remaining.Name = "remaining"
	remaining.TarballSize = 1
	if _, err := reservations.Reserve(ctx, publicationToken.Bearer, workspace, publicationRepo, remaining); err != nil {
		t.Fatalf("published npm receipt was double-counted: %v", err)
	}
	if _, err := reservations.ReadPublishedPackageWithToken(ctx, currentReadToken.Bearer, workspace, publicationRepo, remaining.Name); !errors.Is(err, npm.ErrPackageUnavailable) {
		t.Fatalf("pending npm reservation appeared as published metadata: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM registry_npm_publications WHERE reservation_id = `+p(1), publicationReservation.ID); err == nil {
		t.Fatal("npm publication linkage was deleted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_npm_publications SET npm_version_id = `+p(1)+` WHERE reservation_id = `+p(2), uuid.NewString(), publicationReservation.ID); err == nil {
		t.Fatal("npm publication linkage was mutable")
	}
	if err := repos.RevokeRepositoryRole(ctx, owner, workspace, publicationRepo, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.PublishReceipt(ctx, publicationToken.Bearer, workspace, publicationRepo, publicationReservation.ID); !errors.Is(err, repositories.ErrNPMWriteTokenUnavailable) {
		t.Fatalf("revoked publisher retried npm publication: %v", err)
	}
}
