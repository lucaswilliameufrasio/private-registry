package artifacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

func TestGenericArtifactUploadPublishAndAuthorizedRead(t *testing.T) {
	fixture := newArtifactFixture(t)
	publisherID := fixture.userIDs["publisher"]
	readerID := fixture.userIDs["reader"]
	memberID := fixture.userIDs["member"]
	ctx := context.Background()

	javascript := []byte("window.syntheticWidget = true;")
	readme := []byte("Synthetic widget documentation")
	javascriptSession := startFixtureUpload(t, fixture, publisherID, "widget", "2026.10", "dist/widget.js", javascript)
	readmeSession := startFixtureUpload(t, fixture, publisherID, "widget", "2026.10", "README.md", readme)

	if _, err := fixture.service.ReceiveUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID,
		javascriptSession.ID, bytes.NewReader(javascript)); err != nil {
		t.Fatal("receive JavaScript:", err)
	}
	if _, err := fixture.service.ReceiveUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID,
		readmeSession.ID, bytes.NewReader(readme)); err != nil {
		t.Fatal("receive README:", err)
	}
	if _, err := fixture.service.GetPublishedVersion(ctx, readerID, fixture.workspaceID, fixture.repositoryID,
		javascriptSession.ArtifactVersionID); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("unpublished artifact query error = %v; want ErrArtifactNotFound", err)
	}

	published, err := fixture.service.Publish(ctx, publisherID, fixture.workspaceID, fixture.repositoryID,
		javascriptSession.ArtifactVersionID)
	if err != nil {
		t.Fatal("publish artifact version:", err)
	}
	if published.Status != "published" || published.PublishedAt == nil || len(published.Files) != 2 {
		t.Fatalf("published artifact metadata = %+v; want published version with two files", published)
	}
	if published.Files[0].Path != "README.md" || published.Files[1].Path != "dist/widget.js" {
		t.Fatalf("published file paths = %+v; want stable path order", published.Files)
	}

	readable, err := fixture.service.GetPublishedVersion(ctx, readerID, fixture.workspaceID, fixture.repositoryID, published.ID)
	if err != nil {
		t.Fatal("read published manifest:", err)
	}
	if readable.ID != published.ID || len(readable.Files) != 2 {
		t.Fatalf("read manifest = %+v; want published artifact %+v", readable, published)
	}

	javascriptFile := published.Files[1]
	opened, err := fixture.service.OpenFile(ctx, readerID, fixture.workspaceID, fixture.repositoryID,
		javascriptFile.ID, 0, javascriptFile.Size)
	if err != nil {
		t.Fatal("open authorized artifact file:", err)
	}
	fullBytes, err := io.ReadAll(opened.Reader)
	if closeErr := opened.Reader.Close(); closeErr != nil {
		t.Fatal("close full artifact stream:", closeErr)
	}
	if err != nil {
		t.Fatal("read authorized artifact file:", err)
	}
	if !bytes.Equal(fullBytes, javascript) {
		t.Fatalf("downloaded bytes = %q; want %q", fullBytes, javascript)
	}

	rangeOpened, err := fixture.service.OpenFile(ctx, readerID, fixture.workspaceID, fixture.repositoryID,
		javascriptFile.ID, 7, 9)
	if err != nil {
		t.Fatal("open authorized artifact range:", err)
	}
	rangeBytes, err := io.ReadAll(rangeOpened.Reader)
	if closeErr := rangeOpened.Reader.Close(); closeErr != nil {
		t.Fatal("close ranged artifact stream:", closeErr)
	}
	if err != nil {
		t.Fatal("read authorized artifact range:", err)
	}
	if !rangeOpened.Range || !bytes.Equal(rangeBytes, javascript[7:16]) {
		t.Fatalf("range response = %q (range=%t); want %q", rangeBytes, rangeOpened.Range, javascript[7:16])
	}

	opensBeforeDeniedRead := fixture.storage.opens.Load()
	if _, err := fixture.service.OpenFile(ctx, memberID, fixture.workspaceID, fixture.repositoryID,
		javascriptFile.ID, 0, javascriptFile.Size); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("ungranted member read error = %v; want ErrForbidden", err)
	}
	if opensAfterDeniedRead := fixture.storage.opens.Load(); opensAfterDeniedRead != opensBeforeDeniedRead {
		t.Fatalf("denied read opened storage %d times; want no storage access", opensAfterDeniedRead-opensBeforeDeniedRead)
	}

	ticket, err := fixture.service.IssueDownloadTicket(ctx, readerID, fixture.workspaceID, fixture.repositoryID,
		published.ID, javascriptFile.ID, 0)
	if err != nil {
		t.Fatal("issue short-lived download ticket:", err)
	}
	if len(ticket.Token) != 43 || !ticket.ExpiresAt.After(time.Now()) || ticket.ExpiresAt.After(time.Now().Add(6*time.Minute)) {
		t.Fatalf("download ticket metadata is invalid: token length=%d expires=%s", len(ticket.Token), ticket.ExpiresAt)
	}
	storedHash, err := hashDownloadToken(ticket.Token)
	if err != nil {
		t.Fatal("hash issued download token:", err)
	}
	var storedToken string
	if err := fixture.db.QueryRowContext(ctx,
		"SELECT token_sha256 FROM registry_generic_download_tickets WHERE token_sha256 = ?", storedHash).Scan(&storedToken); err != nil {
		t.Fatal("read stored download token hash:", err)
	}
	if storedToken == ticket.Token || storedToken != storedHash {
		t.Fatal("download ticket was not stored as a SHA-256 hash")
	}
	resolvedFile, expiry, err := fixture.service.ResolveDownloadTicket(ctx, ticket.Token)
	if err != nil {
		t.Fatal("resolve download ticket:", err)
	}
	if resolvedFile.ID != javascriptFile.ID || !expiry.Equal(ticket.ExpiresAt) {
		t.Fatalf("resolved ticket = %+v, %s; want file %s expiry %s", resolvedFile, expiry, javascriptFile.ID, ticket.ExpiresAt)
	}
	ticketOpened, ticketExpiry, err := fixture.service.OpenDownloadTicket(ctx, ticket.Token, 0, javascriptFile.Size)
	if err != nil {
		t.Fatal("open ticket-authorized artifact:", err)
	}
	ticketBytes, err := io.ReadAll(ticketOpened.Reader)
	if closeErr := ticketOpened.Reader.Close(); closeErr != nil {
		t.Fatal("close ticket-authorized artifact:", closeErr)
	}
	if err != nil || !bytes.Equal(ticketBytes, javascript) || !ticketExpiry.Equal(ticket.ExpiresAt) {
		t.Fatalf("ticket download = %q expiry=%s err=%v; want %q expiry=%s", ticketBytes, ticketExpiry, err, javascript, ticket.ExpiresAt)
	}
	if _, err := fixture.service.IssueDownloadTicket(ctx, memberID, fixture.workspaceID, fixture.repositoryID,
		published.ID, javascriptFile.ID, 0); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("ungranted member ticket issue error = %v; want ErrForbidden", err)
	}
	if _, err := fixture.db.ExecContext(ctx,
		"UPDATE registry_generic_download_tickets SET expires_at = ? WHERE token_sha256 = ?",
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), storedHash); err != nil {
		t.Fatal("expire download ticket:", err)
	}
	opensBeforeExpiredTicket := fixture.storage.opens.Load()
	if _, _, err := fixture.service.OpenDownloadTicket(ctx, ticket.Token, 0, javascriptFile.Size); !errors.Is(err, ErrDownloadTicketUnavailable) {
		t.Fatalf("expired ticket open error = %v; want ErrDownloadTicketUnavailable", err)
	}
	if opensAfterExpiredTicket := fixture.storage.opens.Load(); opensAfterExpiredTicket != opensBeforeExpiredTicket {
		t.Fatalf("expired ticket opened storage %d times; want no storage access", opensAfterExpiredTicket-opensBeforeExpiredTicket)
	}
}

func TestGenericArtifactDownloadTicketRemainsDelegatedUntilExpiry(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx := context.Background()
	publisherID := fixture.userIDs["publisher"]
	readerID := fixture.userIDs["reader"]
	payload := []byte("temporary delegated access")
	session := startFixtureUpload(t, fixture, publisherID, "bundle", "v1", "file.bin", payload)
	if _, err := fixture.service.ReceiveUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID, session.ID,
		bytes.NewReader(payload)); err != nil {
		t.Fatal("receive artifact:", err)
	}
	version, err := fixture.service.Publish(ctx, publisherID, fixture.workspaceID, fixture.repositoryID, session.ArtifactVersionID)
	if err != nil {
		t.Fatal("publish artifact:", err)
	}
	ticket, err := fixture.service.IssueDownloadTicket(ctx, readerID, fixture.workspaceID, fixture.repositoryID,
		version.ID, version.Files[0].ID, time.Minute)
	if err != nil {
		t.Fatal("issue download ticket:", err)
	}
	if err := fixture.repositoryService.RevokeRepositoryRole(ctx, fixture.userIDs["owner"], fixture.workspaceID,
		fixture.repositoryID, readerID, repositories.GrantReader); err != nil {
		t.Fatal("revoke reader grant:", err)
	}
	opened, _, err := fixture.service.OpenDownloadTicket(ctx, ticket.Token, 0, int64(len(payload)))
	if err != nil {
		t.Fatalf("read existing delegated ticket after grant revocation: %v", err)
	}
	content, err := io.ReadAll(opened.Reader)
	if closeErr := opened.Reader.Close(); closeErr != nil {
		t.Fatal("close delegated ticket download:", closeErr)
	}
	if err != nil || !bytes.Equal(content, payload) {
		t.Fatalf("delegated ticket content = %q err=%v; want %q", content, err, payload)
	}
}

func TestGenericArtifactUploadCapacityRejectsExcessWithoutQueueingBody(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx := context.Background()
	publisherID := fixture.userIDs["publisher"]
	service, err := New(fixture.db, config.SQLite, fixture.repositoryService, fixture.storage, Options{
		MaxUploadBytes:       1 << 20,
		MaxConcurrentUploads: 1,
	})
	if err != nil {
		t.Fatal("create single-slot artifact service:", err)
	}
	payload := []byte("bounded upload")
	first := startFixtureUpload(t, fixture, publisherID, "capacity", "v1", "first.bin", payload)
	second := startFixtureUpload(t, fixture, publisherID, "capacity", "v1", "second.bin", payload)

	reader := &blockingReader{
		reader:  bytes.NewReader(payload),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	firstResult := make(chan error, 1)
	go func() {
		_, err := service.ReceiveUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID, first.ID, reader)
		firstResult <- err
	}()
	select {
	case <-reader.started:
	case <-time.After(5 * time.Second):
		close(reader.release)
		t.Fatal("first upload never entered its body reader")
	}

	secondBody := &countingReader{reader: bytes.NewReader(payload)}
	if _, err := service.ReceiveUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID,
		second.ID, secondBody); !errors.Is(err, ErrUploadCapacity) {
		close(reader.release)
		t.Fatalf("excess upload error = %v; want ErrUploadCapacity", err)
	}
	if secondBody.bytesRead.Load() != 0 {
		close(reader.release)
		t.Fatalf("rejected queued upload read %d body bytes; want no read", secondBody.bytesRead.Load())
	}
	close(reader.release)
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatalf("first admitted upload failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("admitted upload did not complete after release")
	}
}

func TestGenericArtifactUploadClaimRejectsConcurrentBodyForSameSession(t *testing.T) {
	fixture := newArtifactFixture(t)
	publisherID := fixture.userIDs["publisher"]
	service, err := New(fixture.db, config.SQLite, fixture.repositoryService, fixture.storage, Options{
		MaxUploadBytes:       1 << 20,
		MaxConcurrentUploads: 2,
	})
	if err != nil {
		t.Fatal("create two-slot artifact service:", err)
	}
	payload := []byte("single claimed upload")
	session := startFixtureUpload(t, fixture, publisherID, "concurrent", "v1", "same.bin", payload)
	reader := &blockingReader{
		reader:  bytes.NewReader(payload),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	firstResult := make(chan error, 1)
	go func() {
		_, err := service.ReceiveUpload(context.Background(), publisherID, fixture.workspaceID, fixture.repositoryID, session.ID, reader)
		firstResult <- err
	}()
	select {
	case <-reader.started:
	case <-time.After(5 * time.Second):
		close(reader.release)
		t.Fatal("first upload never entered its body reader")
	}

	secondBody := &countingReader{reader: bytes.NewReader(payload)}
	if _, err := service.ReceiveUpload(context.Background(), publisherID, fixture.workspaceID, fixture.repositoryID,
		session.ID, secondBody); !errors.Is(err, ErrUploadStateConflict) {
		close(reader.release)
		t.Fatalf("concurrent same-session upload error = %v; want ErrUploadStateConflict", err)
	}
	if secondBody.bytesRead.Load() != 0 {
		close(reader.release)
		t.Fatalf("concurrent same-session request consumed %d bytes; want no read", secondBody.bytesRead.Load())
	}
	close(reader.release)
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatalf("first claimed upload failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first claimed upload did not complete after release")
	}
}

func TestGenericArtifactTransientUploadFailureRestoresClaimForRetry(t *testing.T) {
	fixture := newArtifactFixture(t)
	publisherID := fixture.userIDs["publisher"]
	payload := []byte("retry after transient source failure")
	session := startFixtureUpload(t, fixture, publisherID, "retry", "v1", "artifact.bin", payload)
	if _, err := fixture.service.ReceiveUpload(context.Background(), publisherID, fixture.workspaceID,
		fixture.repositoryID, session.ID, failingReader{}); !errors.Is(err, errTransientUploadRead) {
		t.Fatalf("transient upload read error = %v; want %v", err, errTransientUploadRead)
	}
	var status string
	var claimID sql.NullString
	if err := fixture.db.QueryRowContext(context.Background(),
		"SELECT status, upload_claim_id FROM registry_generic_upload_sessions WHERE upload_session_id = ?", session.ID).
		Scan(&status, &claimID); err != nil {
		t.Fatal("read restored upload session:", err)
	}
	if status != "receiving" || claimID.Valid {
		t.Fatalf("restored upload state = status:%s claim:%v; want receiving with no claim", status, claimID)
	}
	if _, err := fixture.service.ReceiveUpload(context.Background(), publisherID, fixture.workspaceID,
		fixture.repositoryID, session.ID, bytes.NewReader(payload)); err != nil {
		t.Fatal("retry transiently failed upload:", err)
	}
}

func TestGenericArtifactStartUploadExpiresAbandonedClaimBeforePathRetry(t *testing.T) {
	fixture := newArtifactFixture(t)
	publisherID := fixture.userIDs["publisher"]
	payload := []byte("abandoned upload bytes")
	request := requestFor("abandoned", "v1", "artifact.bin", payload)
	abandoned := startFixtureUpload(t, fixture, publisherID, request.Collection, request.Version, request.Path, payload)
	claimID := uuid.NewString()
	if _, err := fixture.db.ExecContext(context.Background(),
		`UPDATE registry_generic_upload_sessions SET status = 'uploading', upload_claim_id = ?, expires_at = ?, updated_at = ?
		 WHERE upload_session_id = ? AND status = 'receiving'`,
		claimID, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano),
		time.Now().UTC().Format(time.RFC3339Nano), abandoned.ID); err != nil {
		t.Fatal("simulate abandoned expired upload claim:", err)
	}

	retried, err := fixture.service.StartUpload(context.Background(), publisherID, fixture.workspaceID,
		fixture.repositoryID, request)
	if err != nil {
		t.Fatalf("start upload retry after abandoned claim: %v", err)
	}
	if retried.ID == abandoned.ID {
		t.Fatal("retry reused an expired upload session")
	}
	var oldStatus string
	var oldClaim sql.NullString
	if err := fixture.db.QueryRowContext(context.Background(),
		"SELECT status, upload_claim_id FROM registry_generic_upload_sessions WHERE upload_session_id = ?", abandoned.ID).
		Scan(&oldStatus, &oldClaim); err != nil {
		t.Fatal("read expired abandoned upload:", err)
	}
	if oldStatus != "expired" || oldClaim.Valid {
		t.Fatalf("abandoned upload reconciliation = status:%s claim:%v; want expired with no claim", oldStatus, oldClaim)
	}
}

func TestGenericArtifactPublicationRechecksRevokedPublisherGrant(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx := context.Background()
	publisherID := fixture.userIDs["publisher"]
	payload := []byte("pending artifact")
	session := startFixtureUpload(t, fixture, publisherID, "bundle", "v1", "file.bin", payload)
	if _, err := fixture.service.ReceiveUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID,
		session.ID, bytes.NewReader(payload)); err != nil {
		t.Fatal("receive artifact:", err)
	}
	if err := fixture.repositoryService.RevokeRepositoryRole(ctx, fixture.userIDs["owner"], fixture.workspaceID,
		fixture.repositoryID, publisherID, repositories.GrantPublisher); err != nil {
		t.Fatal("revoke publisher grant:", err)
	}
	if _, err := fixture.service.Publish(ctx, publisherID, fixture.workspaceID, fixture.repositoryID,
		session.ArtifactVersionID); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("publish after grant revocation error = %v; want ErrForbidden", err)
	}
	if _, err := fixture.service.GetPublishedVersion(ctx, fixture.userIDs["reader"], fixture.workspaceID,
		fixture.repositoryID, session.ArtifactVersionID); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("reader query after denied publication = %v; want ErrArtifactNotFound", err)
	}
}

func TestGenericArtifactRejectsDigestMismatchAndReleasesPathReservation(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx := context.Background()
	publisherID := fixture.userIDs["publisher"]
	declared := []byte("declared contents")
	actual := []byte("changed content!!")
	request := requestFor("release", "v1", "artifact.bin", declared)
	session, err := fixture.service.StartUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID, request)
	if err != nil {
		t.Fatal("start mismatched upload:", err)
	}
	if _, err := fixture.service.ReceiveUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID,
		session.ID, bytes.NewReader(actual)); !errors.Is(err, ErrUploadDigestMismatch) {
		t.Fatalf("mismatched upload error = %v; want ErrUploadDigestMismatch", err)
	}
	var rejectedStatus string
	var rejectedDigest string
	var rejectedSize int64
	if err := fixture.db.QueryRowContext(ctx,
		"SELECT status, object_sha256, object_size FROM registry_generic_upload_sessions WHERE upload_session_id = ?", session.ID).
		Scan(&rejectedStatus, &rejectedDigest, &rejectedSize); err != nil {
		t.Fatal("read rejected upload receipt:", err)
	}
	actualDigest := sha256.Sum256(actual)
	if rejectedStatus != "rejected" || rejectedDigest != hex.EncodeToString(actualDigest[:]) || rejectedSize != int64(len(actual)) {
		t.Fatalf("rejected receipt = status:%s sha256:%s size:%d; want actual object metadata", rejectedStatus, rejectedDigest, rejectedSize)
	}
	corrected, err := fixture.service.StartUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID, request)
	if err != nil {
		t.Fatalf("retry corrected upload path: %v", err)
	}
	if corrected.ArtifactVersionID != session.ArtifactVersionID {
		t.Fatalf("corrected upload reserved version %q; want %q", corrected.ArtifactVersionID, session.ArtifactVersionID)
	}
}

func TestGenericArtifactRejectsPathTraversalAndCaseCollisions(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx := context.Background()
	publisherID := fixture.userIDs["publisher"]
	for _, invalidPath := range []string{"../secret", "/absolute", "folder\\file", "C:/file", "CON.txt", "a//b", "./file", "a/../b", "non-ascii-å"} {
		request := requestFor("release", "v1", invalidPath, []byte("data"))
		if _, err := fixture.service.StartUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID, request); !errors.Is(err, ErrInvalidArtifactPath) {
			t.Errorf("path %q error = %v; want ErrInvalidArtifactPath", invalidPath, err)
		}
	}

	first := startFixtureUpload(t, fixture, publisherID, "case-test", "v1", "Dist/App.js", []byte("one"))
	secondRequest := requestFor("case-test", "v1", "dist/app.js", []byte("two"))
	if _, err := fixture.service.StartUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID, secondRequest); !errors.Is(err, ErrPathConflict) {
		t.Fatalf("case-colliding path error = %v; want ErrPathConflict (version %s)", err, first.ArtifactVersionID)
	}
}

func TestGenericArtifactRejectsIncompleteAndExpiredUploads(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx := context.Background()
	publisherID := fixture.userIDs["publisher"]
	active := startFixtureUpload(t, fixture, publisherID, "release", "v1", "active.bin", []byte("complete"))
	if _, err := fixture.service.Publish(ctx, publisherID, fixture.workspaceID, fixture.repositoryID,
		active.ArtifactVersionID); !errors.Is(err, ErrVersionIncomplete) {
		t.Fatalf("publish with active upload error = %v; want ErrVersionIncomplete", err)
	}

	if _, err := fixture.db.ExecContext(ctx,
		"UPDATE registry_generic_upload_sessions SET expires_at = ? WHERE upload_session_id = ?",
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), active.ID); err != nil {
		t.Fatal("expire upload session:", err)
	}
	if _, err := fixture.service.ReceiveUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID,
		active.ID, bytes.NewReader([]byte("complete"))); !errors.Is(err, ErrUploadExpired) {
		t.Fatalf("expired upload receive error = %v; want ErrUploadExpired", err)
	}
	retry, err := fixture.service.StartUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID,
		requestFor("release", "v1", "active.bin", []byte("complete")))
	if err != nil {
		t.Fatalf("start upload after expiration: %v", err)
	}
	if retry.ArtifactVersionID != active.ArtifactVersionID {
		t.Fatalf("retry version = %s; want %s", retry.ArtifactVersionID, active.ArtifactVersionID)
	}
}

func TestGenericArtifactPublishesZeroByteFile(t *testing.T) {
	fixture := newArtifactFixture(t)
	ctx := context.Background()
	publisherID := fixture.userIDs["publisher"]
	payload := []byte{}
	session := startFixtureUpload(t, fixture, publisherID, "empty-file", "v1", "empty.txt", payload)
	if _, err := fixture.service.ReceiveUpload(ctx, publisherID, fixture.workspaceID, fixture.repositoryID,
		session.ID, bytes.NewReader(payload)); err != nil {
		t.Fatal("receive zero-byte file:", err)
	}
	version, err := fixture.service.Publish(ctx, publisherID, fixture.workspaceID, fixture.repositoryID, session.ArtifactVersionID)
	if err != nil {
		t.Fatal("publish zero-byte file:", err)
	}
	if len(version.Files) != 1 || version.Files[0].Size != 0 {
		t.Fatalf("zero-byte manifest = %+v; want one file of size zero", version.Files)
	}
	opened, err := fixture.service.OpenFile(ctx, fixture.userIDs["reader"], fixture.workspaceID,
		fixture.repositoryID, version.Files[0].ID, 0, 0)
	if err != nil {
		t.Fatal("open zero-byte file:", err)
	}
	content, err := io.ReadAll(opened.Reader)
	if closeErr := opened.Reader.Close(); closeErr != nil {
		t.Fatal("close zero-byte file:", closeErr)
	}
	if err != nil || len(content) != 0 {
		t.Fatalf("zero-byte file content = %q err=%v", content, err)
	}
}

type artifactFixture struct {
	db                *sql.DB
	service           *Service
	storage           *countingStorage
	repositoryService *repositories.Service
	userIDs           map[string]string
	workspaceID       string
	repositoryID      string
}

type countingStorage struct {
	storage.Driver
	opens atomic.Int64
}

type blockingReader struct {
	reader  *bytes.Reader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockingReader) Read(buffer []byte) (int, error) {
	r.once.Do(func() {
		close(r.started)
	})
	<-r.release
	return r.reader.Read(buffer)
}

type countingReader struct {
	reader    *bytes.Reader
	bytesRead atomic.Int64
}

var errTransientUploadRead = errors.New("synthetic transient upload read failure")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errTransientUploadRead
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	count, err := r.reader.Read(buffer)
	r.bytesRead.Add(int64(count))
	return count, err
}

func (s *countingStorage) Open(ctx context.Context, key storage.ObjectKey) (io.ReadCloser, storage.ObjectInfo, error) {
	s.opens.Add(1)
	return s.Driver.Open(ctx, key)
}

func (s *countingStorage) OpenRange(ctx context.Context, key storage.ObjectKey, offset int64, length int64) (io.ReadCloser, storage.ObjectInfo, error) {
	s.opens.Add(1)
	return s.Driver.OpenRange(ctx, key, offset, length)
}

func newArtifactFixture(t *testing.T) artifactFixture {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	dbConfig := config.Config{
		DataDir:              dataDir,
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          filepath.Join(dataDir, "registry.sqlite"),
		DatabaseMaxOpenConns: 4,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	db, err := database.Open(ctx, dbConfig)
	if err != nil {
		t.Fatal("open SQLite database:", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close SQLite database: %v", err)
		}
	})
	if _, err := migrations.Migrate(ctx, db, dbConfig); err != nil {
		t.Fatal("apply migrations:", err)
	}

	fixture := artifactFixture{
		db:           db,
		userIDs:      make(map[string]string),
		workspaceID:  uuid.NewString(),
		repositoryID: uuid.NewString(),
	}
	for _, name := range []string{"owner", "publisher", "reader", "member"} {
		userID := uuid.NewString()
		fixture.userIDs[name] = userID
		createdAt := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := db.ExecContext(ctx,
			"INSERT INTO registry_users (user_id, display_name, email, email_verified, status, created_at, updated_at) VALUES (?, ?, NULL, 0, 'active', ?, ?)",
			userID, "Synthetic "+name, createdAt, createdAt); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
	}
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx,
		"INSERT INTO registry_workspaces (workspace_id, slug, display_name, status, created_by, created_at) VALUES (?, 'artifact-workspace', 'Artifact Workspace', 'active', ?, ?)",
		fixture.workspaceID, fixture.userIDs["owner"], createdAt); err != nil {
		t.Fatal("seed workspace:", err)
	}
	for name, role := range map[string]string{"owner": "owner", "publisher": "member", "reader": "member", "member": "member"} {
		if _, err := db.ExecContext(ctx,
			"INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, status, created_by, created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?, ?)",
			fixture.workspaceID, fixture.userIDs[name], role, fixture.userIDs["owner"], createdAt, createdAt); err != nil {
			t.Fatalf("seed %s membership: %v", name, err)
		}
	}
	if _, err := db.ExecContext(ctx,
		"INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, visibility, status, created_by, created_at, updated_at) VALUES (?, ?, 'artifacts', 'Artifacts', 'private', 'active', ?, ?, ?)",
		fixture.repositoryID, fixture.workspaceID, fixture.userIDs["owner"], createdAt, createdAt); err != nil {
		t.Fatal("seed repository:", err)
	}
	for _, grant := range []struct {
		user string
		role string
	}{{"publisher", "publisher"}, {"reader", "reader"}} {
		grantID := uuid.NewString()
		if _, err := db.ExecContext(ctx,
			"INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			grantID, fixture.repositoryID, fixture.workspaceID, fixture.userIDs[grant.user], grant.role, fixture.userIDs["owner"], createdAt); err != nil {
			t.Fatalf("seed %s grant: %v", grant.role, err)
		}
	}

	fixture.repositoryService, err = repositories.New(db, config.SQLite)
	if err != nil {
		t.Fatal("create repository service:", err)
	}
	filesystem, err := storage.NewFileSystem(filepath.Join(root, "object-store"))
	if err != nil {
		t.Fatal("create filesystem store:", err)
	}
	fixture.storage = &countingStorage{Driver: filesystem}
	fixture.service, err = New(db, config.SQLite, fixture.repositoryService, fixture.storage, Options{
		MaxUploadBytes:       1 << 20,
		MaxConcurrentUploads: 2,
	})
	if err != nil {
		t.Fatal("create artifact service:", err)
	}
	return fixture
}

func startFixtureUpload(t *testing.T, fixture artifactFixture, actorID string, collection string, version string, filePath string, payload []byte) UploadSession {
	t.Helper()
	session, err := fixture.service.StartUpload(context.Background(), actorID, fixture.workspaceID, fixture.repositoryID,
		requestFor(collection, version, filePath, payload))
	if err != nil {
		t.Fatal("start artifact upload:", err)
	}
	return session
}

func requestFor(collection string, version string, filePath string, payload []byte) StartUploadRequest {
	digest := sha256.Sum256(payload)
	return StartUploadRequest{
		Collection:  collection,
		Version:     version,
		Path:        filePath,
		ContentType: "application/octet-stream",
		Size:        int64(len(payload)),
		SHA256:      hex.EncodeToString(digest[:]),
	}
}
