package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/backup"
	"private-registry/internal/config"
	"private-registry/internal/pub"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

type blockedPubReader struct {
	reader  io.Reader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type observedPubBoundaryReader struct{ reads int }

func (r *observedPubBoundaryReader) Read([]byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

type cancelPubReader struct {
	reader io.Reader
	cancel context.CancelFunc
	once   sync.Once
}

func (r *cancelPubReader) Read(buffer []byte) (int, error) {
	r.once.Do(r.cancel)
	return r.reader.Read(buffer)
}

func (r *blockedPubReader) Read(buffer []byte) (int, error) {
	r.once.Do(func() {
		close(r.started)
		<-r.release
	})
	return r.reader.Read(buffer)
}

func TestSQLitePubReceiptBoundaryV37(t *testing.T) {
	fixture := newArtifactFixture(t)
	exercisePubReceiptBoundaryV37(t, fixture.db, config.SQLite, fixture.repositoryService, fixture.storage, fixture.workspaceID, fixture.userIDs["owner"], fixture.userIDs["publisher"])
}

func exercisePubReceiptBoundaryV37(t *testing.T, db *sql.DB, driver config.DatabaseDriver, repos *repositories.Service, objects storage.Driver, workspace, owner, publisher string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	p := func(n int) string {
		if driver == config.Postgres {
			return fmt.Sprintf("$%d", n)
		}
		return "?"
	}
	repository := uuid.NewString()
	query := `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format, review_required) VALUES (` + p(1) + `, ` + p(2) + `, 'pub-receive-v37', 'Pub', ` + p(3) + `, 'now', 'now', 'pub', 1)`
	if _, err := db.ExecContext(ctx, query, repository, workspace, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, repository, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	token, err := repos.IssuePubWriteToken(ctx, publisher, workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("name: fixture\nversion: 1.0.0\n")
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	w := tar.NewWriter(gz)
	if err := w.WriteHeader(&tar.Header{Name: "pubspec.yaml", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	content := buffer.Bytes()
	digest, metadata := sha256.Sum256(content), sha256.Sum256(manifest)
	request := pub.ReservationRequest{Name: "fixture", Version: "1.0.0", TarballSHA256: hex.EncodeToString(digest[:]), TarballSize: int64(len(content)), MetadataSHA256: hex.EncodeToString(metadata[:])}
	reservations, err := pub.NewReservationService(db, repos, driver)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	atomicUpload, err := reservations.StartNativeUpload(ctx, token.Bearer, workspace, repository)
	if err != nil {
		t.Fatal(err)
	}
	atomicRequest := request
	atomicRequest.Name = "native_atomic_fixture"
	atomicReservation, err := reservations.ReserveNativeUpload(ctx, token.Bearer, workspace, repository, atomicUpload, atomicRequest)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := reservations.ReserveNativeUpload(ctx, token.Bearer, workspace, repository, atomicUpload, atomicRequest)
	if err != nil || retry.ID != atomicReservation.ID {
		t.Fatalf("native reservation retry changed identity: %v", err)
	}
	conflictingRequest := atomicRequest
	conflictingRequest.Name = "native_conflicting_fixture"
	if _, err := reservations.ReserveNativeUpload(ctx, token.Bearer, workspace, repository, atomicUpload, conflictingRequest); !errors.Is(err, pub.ErrReservationConflict) {
		t.Fatalf("native session accepted a second reservation: %v", err)
	}
	var orphanCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_pub_reservations WHERE repository_id = `+p(1)+` AND name = `+p(2), repository, conflictingRequest.Name).Scan(&orphanCount); err != nil || orphanCount != 0 {
		t.Fatalf("conflicting native binding left an orphan: count=%d err=%v", orphanCount, err)
	}
	if err := reservations.Cancel(ctx, token.Bearer, workspace, repository, atomicReservation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.StartNativeUpload(context.Background(), token.Bearer, workspace, repository); !errors.Is(err, pub.ErrNativeUploadUnavailable) {
		t.Fatalf("native upload accepted missing deadline: %v", err)
	}
	uploadID, err := reservations.StartNativeUpload(ctx, token.Bearer, workspace, repository)
	if err != nil {
		t.Fatal(err)
	}
	otherNativeToken, err := repos.IssuePubWriteToken(ctx, publisher, workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := reservations.CheckNativeUpload(ctx, otherNativeToken.Bearer, workspace, repository, uploadID); !errors.Is(err, pub.ErrNativeUploadUnavailable) {
		t.Fatalf("native upload accepted a different credential: %v", err)
	}
	if err := reservations.BindNativeUpload(ctx, token.Bearer, workspace, repository, uploadID, reservation.ID); err != nil {
		t.Fatal(err)
	}
	if err := reservations.BindNativeUpload(ctx, token.Bearer, workspace, repository, uploadID, reservation.ID); err != nil {
		t.Fatalf("native upload binding was not idempotent: %v", err)
	}
	if got, err := reservations.NativeUploadReservation(ctx, token.Bearer, workspace, repository, uploadID); err != nil || got != reservation.ID {
		t.Fatalf("bound native upload was not found: %v", err)
	}
	if received, err := reservations.NativeUploadReceived(ctx, token.Bearer, workspace, repository, uploadID, reservation.ID); err != nil || received {
		t.Fatalf("unreceived native upload was reported as received: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_pub_native_uploads SET recovery_invalidated = 1 WHERE upload_id = `+p(1), uploadID); err != nil {
		t.Fatal(err)
	}
	if err := reservations.CheckNativeUpload(ctx, token.Bearer, workspace, repository, uploadID); !errors.Is(err, pub.ErrNativeUploadUnavailable) {
		t.Fatalf("invalidated native upload remained usable: %v", err)
	}
	stage := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	countedObjects := &countingStorage{Driver: objects}
	unsafeStage := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(unsafeStage, 0o755); err != nil {
		t.Fatal(err)
	}
	symlinkStage := filepath.Join(t.TempDir(), "linked-stage")
	if err := os.Symlink(stage, symlinkStage); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{unsafeStage, symlinkStage} {
		_, err := pub.NewReceiptService(db, repos, driver, countedObjects, pub.ReceiptOptions{StagingDirectory: path, MaxConcurrent: 1, Limits: pub.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}})
		if err == nil {
			t.Fatal("Pub receipt accepted unsafe staging directory")
		}
	}
	receiver, err := pub.NewReceiptService(db, repos, driver, countedObjects, pub.ReceiptOptions{StagingDirectory: stage, MaxConcurrent: 1, Limits: pub.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	input := pub.ReceiptInput{Name: request.Name, Version: request.Version, Manifest: manifest, Size: request.TarballSize}
	observed := &observedPubBoundaryReader{}
	if err := receiver.Receive(context.Background(), token.Bearer, workspace, repository, reservation.ID, input, observed); !errors.Is(err, pub.ErrReservationUnavailable) || observed.reads != 0 {
		t.Fatalf("Pub receipt without deadline consumed body: reads=%d err=%v", observed.reads, err)
	}
	observed = &observedPubBoundaryReader{}
	if err := receiver.Receive(ctx, "invalid", workspace, repository, reservation.ID, input, observed); !errors.Is(err, repositories.ErrPubWriteTokenUnavailable) || observed.reads != 0 {
		t.Fatalf("unauthorized Pub receipt consumed body: reads=%d err=%v", observed.reads, err)
	}
	observed = &observedPubBoundaryReader{}
	if err := receiver.Receive(ctx, token.Bearer, workspace, uuid.NewString(), reservation.ID, input, observed); !errors.Is(err, repositories.ErrPubWriteTokenUnavailable) || observed.reads != 0 {
		t.Fatalf("cross-repository Pub receipt consumed body: reads=%d err=%v", observed.reads, err)
	}
	for _, invalid := range []pub.ReceiptInput{
		{Name: "other", Version: input.Version, Manifest: input.Manifest, Size: input.Size},
		{Name: input.Name, Version: "1.0.1", Manifest: input.Manifest, Size: input.Size},
		{Name: input.Name, Version: input.Version, Manifest: []byte("name: changed\nversion: 1.0.0\n"), Size: input.Size},
		{Name: input.Name, Version: input.Version, Manifest: input.Manifest, Size: input.Size + 1},
	} {
		observed = &observedPubBoundaryReader{}
		if err := receiver.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, invalid, observed); !errors.Is(err, pub.ErrReservationUnavailable) || observed.reads != 0 {
			t.Fatalf("Pub receipt with mismatched metadata consumed body: reads=%d err=%v", observed.reads, err)
		}
	}
	corrupted := bytes.Clone(content)
	corrupted[len(corrupted)-1] ^= 1
	if err := receiver.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, input, bytes.NewReader(corrupted)); err == nil {
		t.Fatal("corrupt Pub archive accepted")
	}
	for _, body := range [][]byte{content[:len(content)-1], append(bytes.Clone(content), 0)} {
		if err := receiver.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, input, bytes.NewReader(body)); err == nil {
			t.Fatal("Pub receipt accepted a body with an incorrect size")
		}
		var state string
		var verified int
		if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_pub_reservations WHERE reservation_id = `+p(1), reservation.ID).Scan(&state, &verified); err != nil || state != "reserved" || verified != 0 {
			t.Fatalf("incorrect-size Pub body left a receipt: status=%q verified=%d err=%v", state, verified, err)
		}
	}
	badReceiver, err := pub.NewReceiptService(db, repos, driver, corruptNPMReadback{Driver: objects}, pub.ReceiptOptions{StagingDirectory: stage, MaxConcurrent: 1, Limits: pub.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	if err := badReceiver.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, input, bytes.NewReader(content)); err == nil {
		t.Fatal("Pub receipt accepted corrupt storage readback")
	}
	var preStatus string
	var preVerified int
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_pub_reservations WHERE reservation_id = `+p(1), reservation.ID).Scan(&preStatus, &preVerified); err != nil || preStatus != "reserved" || preVerified != 0 {
		t.Fatalf("failed Pub readback left a receipt: status=%q verified=%d err=%v", preStatus, preVerified, err)
	}
	if driver == config.Postgres {
		if _, err := db.ExecContext(ctx, `CREATE FUNCTION fixture_reject_pub_receipt_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'pub.receipt.verified' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER fixture_reject_pub_receipt_audit BEFORE INSERT ON registry_audit_events FOR EACH ROW EXECUTE FUNCTION fixture_reject_pub_receipt_audit()`); err != nil {
			t.Fatal(err)
		}
	} else if _, err := db.ExecContext(ctx, `CREATE TRIGGER fixture_reject_pub_receipt_audit BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'pub.receipt.verified' BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, input, bytes.NewReader(content)); err == nil {
		t.Fatal("Pub receipt was accepted without audit")
	}
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_pub_reservations WHERE reservation_id = `+p(1), reservation.ID).Scan(&preStatus, &preVerified); err != nil || preStatus != "reserved" || preVerified != 0 {
		t.Fatalf("failed Pub audit left a receipt: status=%q verified=%d err=%v", preStatus, preVerified, err)
	}
	if driver == config.Postgres {
		if _, err := db.ExecContext(ctx, `DROP TRIGGER fixture_reject_pub_receipt_audit ON registry_audit_events`); err != nil {
			t.Fatal(err)
		}
	} else if _, err := db.ExecContext(ctx, `DROP TRIGGER fixture_reject_pub_receipt_audit`); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, input, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	reviewUpload, err := reservations.StartNativeUpload(ctx, token.Bearer, workspace, repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := reservations.BindNativeUpload(ctx, token.Bearer, workspace, repository, reviewUpload, reservation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.PublishNativeUpload(ctx, token.Bearer, workspace, repository, reviewUpload); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("native publication bypassed pending review: %v", err)
	}
	var status, stored string
	var verified, hold int
	query = `SELECT status, manifest, object_verified, review_hold FROM registry_pub_reservations WHERE reservation_id = ` + p(1)
	if err := db.QueryRowContext(ctx, query, reservation.ID).Scan(&status, &stored, &verified, &hold); err != nil || status != "uploaded" || stored != string(manifest) || verified != 1 || hold != 1 {
		t.Fatalf("Pub receipt differs: status=%q verified=%d hold=%d err=%v", status, verified, hold, err)
	}
	var auditCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_audit_events WHERE action = 'pub.receipt.verified' AND target_id = `+p(1), reservation.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("Pub receipt audit count differs: count=%d err=%v", auditCount, err)
	}
	if _, _, err := reservations.ListReviewCandidates(ctx, owner, workspace, repository, "", 10); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("ungranted user listed Pub review candidates: %v", err)
	}
	beforeReviewOpen := countedObjects.opens.Load()
	if reader, _, err := receiver.OpenReviewArchive(ctx, owner, workspace, repository, reservation.ID); !errors.Is(err, repositories.ErrForbidden) || reader != nil || countedObjects.opens.Load() != beforeReviewOpen {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("ungranted reviewer accessed Pub storage: %v", err)
	}
	if _, err := repos.GrantPubReviewer(ctx, owner, workspace, repository, publisher); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, publisher, workspace, repository, reservation.ID, "approved", ""); !errors.Is(err, pub.ErrReviewUnavailable) {
		t.Fatalf("publisher approved own Pub receipt: %v", err)
	}
	if _, err := repos.GrantPubReviewer(ctx, owner, workspace, repository, owner); err != nil {
		t.Fatal(err)
	}
	candidates, _, err := reservations.ListReviewCandidates(ctx, owner, workspace, repository, "", 10)
	if err != nil || len(candidates) != 1 || candidates[0].ID != reservation.ID {
		t.Fatalf("Pub review candidate missing: %v", err)
	}
	reviewReader, reviewSize, err := receiver.OpenReviewArchive(ctx, owner, workspace, repository, reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	reviewBytes, readErr := io.ReadAll(reviewReader)
	closeErr := reviewReader.Close()
	if readErr != nil || closeErr != nil || reviewSize != int64(len(content)) || !bytes.Equal(reviewBytes, content) {
		t.Fatalf("Pub review archive differs: read=%v close=%v", readErr, closeErr)
	}
	if driver == config.Postgres {
		if _, err := db.ExecContext(ctx, `CREATE FUNCTION fixture_reject_pub_review_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'pub.review.approved' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER fixture_reject_pub_review_audit BEFORE INSERT ON registry_audit_events FOR EACH ROW EXECUTE FUNCTION fixture_reject_pub_review_audit()`); err != nil {
			t.Fatal(err)
		}
	} else if _, err := db.ExecContext(ctx, `CREATE TRIGGER fixture_reject_pub_review_audit BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'pub.review.approved' BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "approved", ""); err == nil {
		t.Fatal("Pub review succeeded without audit")
	}
	var reviewCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_pub_review_decisions WHERE reservation_id = `+p(1), reservation.ID).Scan(&reviewCount); err != nil || reviewCount != 0 {
		t.Fatalf("failed review audit left a decision: count=%d err=%v", reviewCount, err)
	}
	if driver == config.Postgres {
		if _, err := db.ExecContext(ctx, `DROP TRIGGER fixture_reject_pub_review_audit ON registry_audit_events`); err != nil {
			t.Fatal(err)
		}
	} else if _, err := db.ExecContext(ctx, `DROP TRIGGER fixture_reject_pub_review_audit`); err != nil {
		t.Fatal(err)
	}
	approval, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "approved", "")
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "approved", ""); err != nil || retry != approval {
		t.Fatalf("Pub review approval retry differs: %v", err)
	}
	checkApproval := func() error {
		return repos.WithPubWriteTokenTransaction(ctx, token.Bearer, workspace, repository, func(tx *sql.Tx, actor string) error {
			return reservations.RequireCurrentApproval(ctx, tx, workspace, repository, reservation.ID, actor)
		})
	}
	if err := checkApproval(); err != nil {
		t.Fatalf("current Pub approval rejected: %v", err)
	}
	if _, err := repos.SetPubReviewPolicy(ctx, owner, workspace, repository, 0, false); err != nil {
		t.Fatal(err)
	}
	if err := checkApproval(); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("Pub policy change left old approval valid: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	if err := repos.RevokePubReviewer(ctx, owner, workspace, repository, owner); err != nil {
		t.Fatal(err)
	}
	beforeReviewOpen = countedObjects.opens.Load()
	if reader, _, err := receiver.OpenReviewArchive(ctx, owner, workspace, repository, reservation.ID); !errors.Is(err, repositories.ErrForbidden) || reader != nil || countedObjects.opens.Load() != beforeReviewOpen {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("revoked reviewer accessed Pub storage: %v", err)
	}
	if err := checkApproval(); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("revoked Pub reviewer left approval valid: %v", err)
	}
	if _, err := repos.GrantPubReviewer(ctx, owner, workspace, repository, owner); err != nil {
		t.Fatal(err)
	}
	if err := checkApproval(); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("Pub reviewer regrant revived old approval: %v", err)
	}
	type decisionResult struct {
		decision string
		err      error
	}
	decisions := make(chan decisionResult, 2)
	for _, decision := range []string{"approved", "rejected"} {
		go func(decision string) {
			reason := ""
			if decision == "rejected" {
				reason = "synthetic rejection"
			}
			_, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, decision, reason)
			decisions <- decisionResult{decision: decision, err: err}
		}(decision)
	}
	for range 2 {
		result := <-decisions
		if result.decision == "rejected" && result.err != nil {
			t.Fatalf("concurrent Pub rejection failed: %v", result.err)
		}
		if result.decision == "approved" && result.err != nil && !errors.Is(result.err, pub.ErrReviewUnavailable) {
			t.Fatalf("concurrent Pub approval failed unexpectedly: %v", result.err)
		}
	}
	if _, err := reservations.DecideReview(ctx, owner, workspace, repository, reservation.ID, "approved", ""); !errors.Is(err, pub.ErrReviewUnavailable) {
		t.Fatalf("rejected Pub receipt was approved afterward: %v", err)
	}
	if _, err := reservations.PublishReceipt(ctx, token.Bearer, workspace, repository, reservation.ID); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("rejected Pub receipt was published: %v", err)
	}
	beforeReviewOpen = countedObjects.opens.Load()
	if reader, _, err := receiver.OpenReviewArchive(ctx, owner, workspace, repository, reservation.ID); !errors.Is(err, pub.ErrReviewUnavailable) || reader != nil || countedObjects.opens.Load() != beforeReviewOpen {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("rejected Pub receipt accessed review storage: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET logical_quota_bytes = `+p(1)+` WHERE repository_id = `+p(2), request.TarballSize, repository); err != nil {
		t.Fatal(err)
	}
	quotaRequest := request
	quotaRequest.Name = "quota_fixture"
	quotaRequest.TarballSize = 1
	if _, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, quotaRequest); !errors.Is(err, pub.ErrReservationQuota) {
		t.Fatalf("verified pending Pub receipt did not consume quota: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET logical_quota_bytes = `+p(1)+` WHERE repository_id = `+p(2), request.TarballSize+1, repository); err != nil {
		t.Fatal(err)
	}
	quotaReservation, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, quotaRequest)
	if err != nil {
		t.Fatalf("remaining Pub quota was rejected: %v", err)
	}
	if err := reservations.Cancel(ctx, token.Bearer, workspace, repository, quotaReservation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET logical_quota_bytes = NULL WHERE repository_id = `+p(1), repository); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
		t.Fatalf("Pub receipt staging remains: %v", err)
	}
	otherRepository := uuid.NewString()
	query = `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'pub-revoke-v37', 'Pub', ` + p(3) + `, 'now', 'now', 'pub')`
	if _, err := db.ExecContext(ctx, query, otherRepository, workspace, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, otherRepository, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	otherToken, err := repos.IssuePubWriteToken(ctx, publisher, workspace, otherRepository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	otherReservation, err := reservations.Reserve(ctx, otherToken.Bearer, workspace, otherRepository, request)
	if err != nil {
		t.Fatal(err)
	}
	revoking := &revokeNPMReader{reader: bytes.NewReader(content), revoke: func() error {
		return repos.RevokeRepositoryRole(ctx, owner, workspace, otherRepository, publisher, repositories.GrantPublisher)
	}}
	if err := receiver.Receive(ctx, otherToken.Bearer, workspace, otherRepository, otherReservation.ID, input, revoking); !errors.Is(err, repositories.ErrPubWriteTokenUnavailable) {
		t.Fatalf("Pub receipt ignored revocation during upload: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_pub_reservations WHERE reservation_id = `+p(1), otherReservation.ID).Scan(&preStatus, &preVerified); err != nil || preStatus != "reserved" || preVerified != 0 {
		t.Fatalf("revoked Pub upload left receipt: status=%q verified=%d err=%v", preStatus, preVerified, err)
	}
	if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
		t.Fatalf("revoked Pub receipt left staging files: %v", err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, otherRepository, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	observed = &observedPubBoundaryReader{}
	if err := receiver.Receive(ctx, otherToken.Bearer, workspace, otherRepository, otherReservation.ID, input, observed); !errors.Is(err, repositories.ErrPubWriteTokenUnavailable) || observed.reads != 0 {
		t.Fatalf("regranted publisher revived old Pub token: reads=%d err=%v", observed.reads, err)
	}
	concurrentRepository := uuid.NewString()
	query = `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'pub-concurrent-v37', 'Pub', ` + p(3) + `, 'now', 'now', 'pub')`
	if _, err := db.ExecContext(ctx, query, concurrentRepository, workspace, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, concurrentRepository, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	concurrentToken, err := repos.IssuePubWriteToken(ctx, publisher, workspace, concurrentRepository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	concurrentReservation, err := reservations.Reserve(ctx, concurrentToken.Bearer, workspace, concurrentRepository, request)
	if err != nil {
		t.Fatal(err)
	}
	concurrentUpload, err := reservations.StartNativeUpload(ctx, concurrentToken.Bearer, workspace, concurrentRepository)
	if err != nil {
		t.Fatal(err)
	}
	if err := reservations.BindNativeUpload(ctx, concurrentToken.Bearer, workspace, concurrentRepository, concurrentUpload, concurrentReservation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, concurrentRepository, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	readToken, err := repos.IssuePersonalReadToken(ctx, owner, workspace, concurrentRepository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	beforePendingOpen := countedObjects.opens.Load()
	if reader, _, err := receiver.OpenPublishedArchiveWithToken(ctx, readToken.Bearer, workspace, concurrentRepository, request.Name, request.Version); !errors.Is(err, pub.ErrPackageUnavailable) || reader != nil || countedObjects.opens.Load() != beforePendingOpen {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("pending Pub reservation was readable: %v", err)
	}
	if _, err := reservations.ReadPublishedVersionsWithToken(ctx, readToken.Bearer, workspace, concurrentRepository, request.Name); !errors.Is(err, pub.ErrPackageUnavailable) {
		t.Fatalf("pending Pub reservation appeared in metadata: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET logical_quota_bytes = `+p(1)+` WHERE repository_id = `+p(2), request.TarballSize, concurrentRepository); err != nil {
		t.Fatal(err)
	}
	blocked := &blockedPubReader{reader: bytes.NewReader(content), started: make(chan struct{}), release: make(chan struct{})}
	finished := make(chan error, 1)
	go func() {
		finished <- receiver.Receive(ctx, concurrentToken.Bearer, workspace, concurrentRepository, concurrentReservation.ID, input, blocked)
	}()
	select {
	case <-blocked.started:
	case <-ctx.Done():
		close(blocked.release)
		t.Fatal("first Pub upload did not reach its body")
	}
	observed = &observedPubBoundaryReader{}
	err = receiver.Receive(ctx, concurrentToken.Bearer, workspace, concurrentRepository, concurrentReservation.ID, input, observed)
	secondReceiver, createErr := pub.NewReceiptService(db, repos, driver, countedObjects, pub.ReceiptOptions{StagingDirectory: stage, MaxConcurrent: 1, Limits: pub.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}})
	if createErr != nil {
		close(blocked.release)
		<-finished
		t.Fatal(createErr)
	}
	secondObserved := &observedPubBoundaryReader{}
	secondErr := secondReceiver.Receive(ctx, concurrentToken.Bearer, workspace, concurrentRepository, concurrentReservation.ID, input, secondObserved)
	uploadingQuotaRequest := request
	uploadingQuotaRequest.Name = "uploading_quota"
	uploadingQuotaRequest.TarballSize = 1
	_, quotaErr := reservations.Reserve(ctx, concurrentToken.Bearer, workspace, concurrentRepository, uploadingQuotaRequest)
	close(blocked.release)
	firstErr := <-finished
	if !errors.Is(err, pub.ErrReceiptCapacity) || observed.reads != 0 || !errors.Is(secondErr, pub.ErrReservationUnavailable) || secondObserved.reads != 0 || firstErr != nil {
		t.Fatalf("Pub receipt concurrency failed: capacity=%v reads=%d other=%v other_reads=%d first=%v", err, observed.reads, secondErr, secondObserved.reads, firstErr)
	}
	if !errors.Is(quotaErr, pub.ErrReservationQuota) {
		t.Fatalf("uploading Pub reservation did not consume quota: %v", quotaErr)
	}
	if driver == config.Postgres {
		if _, err := db.ExecContext(ctx, `CREATE FUNCTION fixture_reject_pub_publication_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'pub.publication.created' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER fixture_reject_pub_publication_audit BEFORE INSERT ON registry_audit_events FOR EACH ROW EXECUTE FUNCTION fixture_reject_pub_publication_audit()`); err != nil {
			t.Fatal(err)
		}
	} else if _, err := db.ExecContext(ctx, `CREATE TRIGGER fixture_reject_pub_publication_audit BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'pub.publication.created' BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.PublishReceipt(ctx, concurrentToken.Bearer, workspace, concurrentRepository, concurrentReservation.ID); err == nil {
		t.Fatal("Pub publication succeeded without audit")
	}
	var publicationCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_pub_publications WHERE reservation_id = `+p(1), concurrentReservation.ID).Scan(&publicationCount); err != nil || publicationCount != 0 {
		t.Fatalf("failed publication audit left a link: count=%d err=%v", publicationCount, err)
	}
	if driver == config.Postgres {
		if _, err := db.ExecContext(ctx, `DROP TRIGGER fixture_reject_pub_publication_audit ON registry_audit_events`); err != nil {
			t.Fatal(err)
		}
	} else if _, err := db.ExecContext(ctx, `DROP TRIGGER fixture_reject_pub_publication_audit`); err != nil {
		t.Fatal(err)
	}
	type publishResult struct {
		id  string
		err error
	}
	publications := make(chan publishResult, 2)
	for range 2 {
		go func() {
			id, err := reservations.PublishNativeUpload(ctx, concurrentToken.Bearer, workspace, concurrentRepository, concurrentUpload)
			publications <- publishResult{id: id, err: err}
		}()
	}
	first, second := <-publications, <-publications
	if first.err != nil || second.err != nil || first.id == "" || first.id != second.id {
		t.Fatalf("concurrent Pub publication was not idempotent: %v %v", first.err, second.err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_pub_publications WHERE reservation_id = `+p(1), concurrentReservation.ID).Scan(&publicationCount); err != nil || publicationCount != 1 {
		t.Fatalf("Pub publication link count differs: count=%d err=%v", publicationCount, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM registry_audit_events WHERE action = 'pub.publication.created' AND target_id = `+p(1), first.id).Scan(&publicationCount); err != nil || publicationCount != 1 {
		t.Fatalf("Pub publication audit count differs: count=%d err=%v", publicationCount, err)
	}
	snapshot, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := backup.InventoryPub(ctx, snapshot, 100, 100)
	matches := 0
	for _, object := range inventory {
		if object.Key.WorkspaceID == workspace && object.Key.SHA256 == request.TarballSHA256 && object.Size == request.TarballSize {
			matches++
		}
	}
	if err != nil || matches != 1 {
		_ = snapshot.Rollback()
		t.Fatalf("Pub inventory did not deduplicate verified references: matches=%d err=%v", matches, err)
	}
	if _, err := backup.InventoryPub(ctx, snapshot, 100, 1); err == nil {
		_ = snapshot.Rollback()
		t.Fatal("Pub inventory exceeded reference limit")
	}
	if err := snapshot.Rollback(); err != nil {
		t.Fatal(err)
	}
	conflictTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	conflictPackage := uuid.NewString()
	if _, err := conflictTx.ExecContext(ctx, `INSERT INTO registry_pub_packages (package_id, workspace_id, repository_id, name, created_by, created_at) VALUES (`+p(1)+`, `+p(2)+`, `+p(3)+`, 'inventory_conflict', `+p(4)+`, 'now')`, conflictPackage, workspace, concurrentRepository, publisher); err != nil {
		_ = conflictTx.Rollback()
		t.Fatal(err)
	}
	if _, err := conflictTx.ExecContext(ctx, `INSERT INTO registry_pub_versions (pub_version_id, workspace_id, repository_id, package_id, version, version_identity, manifest, tarball_sha256, tarball_size, created_by, created_at) VALUES (`+p(1)+`, `+p(2)+`, `+p(3)+`, `+p(4)+`, '1.0.0', '1.0.0', '{}', `+p(5)+`, `+p(6)+`, `+p(7)+`, 'now')`, uuid.NewString(), workspace, concurrentRepository, conflictPackage, request.TarballSHA256, request.TarballSize+1, publisher); err != nil {
		_ = conflictTx.Rollback()
		t.Fatal(err)
	}
	if _, err := backup.InventoryPub(ctx, conflictTx, 100, 100); err == nil {
		_ = conflictTx.Rollback()
		t.Fatal("Pub inventory accepted conflicting sizes")
	}
	if err := conflictTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	versions, err := reservations.ReadPublishedVersionsWithToken(ctx, readToken.Bearer, workspace, concurrentRepository, request.Name)
	if err != nil || len(versions) != 1 || versions[0].Version != request.Version || versions[0].SHA256 != request.TarballSHA256 || !bytes.Equal(versions[0].Manifest, manifest) {
		t.Fatalf("published Pub metadata differs: %v", err)
	}
	if _, err := reservations.ReadPublishedVersionsWithToken(ctx, concurrentToken.Bearer, workspace, concurrentRepository, request.Name); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("publisher token without reader grant accessed Pub metadata: %v", err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, concurrentRepository, publisher, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.ReadPublishedVersionsWithToken(ctx, concurrentToken.Bearer, workspace, concurrentRepository, request.Name); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("reader grant retroactively expanded Pub token: %v", err)
	}
	readWriteToken, err := repos.IssuePubWriteToken(ctx, publisher, workspace, concurrentRepository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reservations.ReadPublishedVersionsWithToken(ctx, readWriteToken.Bearer, workspace, concurrentRepository, request.Name); err != nil || len(got) != 1 {
		t.Fatalf("Pub token bound to reader grant could not read metadata: %v", err)
	}
	if err := repos.RevokeRepositoryRole(ctx, owner, workspace, concurrentRepository, publisher, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, concurrentRepository, publisher, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.ReadPublishedVersionsWithToken(ctx, readWriteToken.Bearer, workspace, concurrentRepository, request.Name); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("reader grant regrant revived Pub token metadata access: %v", err)
	}
	publishedReader, publishedSize, err := receiver.OpenPublishedArchiveWithToken(ctx, readToken.Bearer, workspace, concurrentRepository, request.Name, request.Version)
	if err != nil {
		t.Fatal(err)
	}
	publishedBytes, readErr := io.ReadAll(publishedReader)
	closeErr = publishedReader.Close()
	if readErr != nil || closeErr != nil || publishedSize != int64(len(content)) || !bytes.Equal(publishedBytes, content) {
		t.Fatalf("published Pub archive differs: read=%v close=%v", readErr, closeErr)
	}
	beforeCrossRepository := countedObjects.opens.Load()
	if reader, _, err := receiver.OpenPublishedArchiveWithToken(ctx, readToken.Bearer, workspace, uuid.NewString(), request.Name, request.Version); err == nil || reader != nil || countedObjects.opens.Load() != beforeCrossRepository {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("cross-repository Pub read reached storage: %v", err)
	}
	if err := repos.RevokeRepositoryRole(ctx, owner, workspace, concurrentRepository, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, concurrentRepository, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	beforeRevokedOpen := countedObjects.opens.Load()
	if reader, _, err := receiver.OpenPublishedArchiveWithToken(ctx, readToken.Bearer, workspace, concurrentRepository, request.Name, request.Version); err == nil || reader != nil || countedObjects.opens.Load() != beforeRevokedOpen {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("revoked reader token reached Pub storage after regrant: %v", err)
	}
	if _, err := reservations.ReadPublishedVersionsWithToken(ctx, readToken.Bearer, workspace, concurrentRepository, request.Name); err == nil {
		t.Fatal("revoked reader token accessed Pub metadata after regrant")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_repositories SET logical_quota_bytes = `+p(1)+` WHERE repository_id = `+p(2), request.TarballSize+1, concurrentRepository); err != nil {
		t.Fatal(err)
	}
	remainingReservation, err := reservations.Reserve(ctx, concurrentToken.Bearer, workspace, concurrentRepository, uploadingQuotaRequest)
	if err != nil {
		t.Fatalf("published Pub receipt was counted twice: %v", err)
	}
	if err := reservations.Cancel(ctx, concurrentToken.Bearer, workspace, concurrentRepository, remainingReservation.ID); err != nil {
		t.Fatal(err)
	}
	cancelRepository := uuid.NewString()
	query = `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (` + p(1) + `, ` + p(2) + `, 'pub-cancel-v37', 'Pub', ` + p(3) + `, 'now', 'now', 'pub')`
	if _, err := db.ExecContext(ctx, query, cancelRepository, workspace, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, owner, workspace, cancelRepository, publisher, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	cancelToken, err := repos.IssuePubWriteToken(ctx, publisher, workspace, cancelRepository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cancelReservation, err := reservations.Reserve(ctx, cancelToken.Bearer, workspace, cancelRepository, request)
	if err != nil {
		t.Fatal(err)
	}
	uploadCtx, cancelUpload := context.WithCancel(ctx)
	cancelledReader := &cancelPubReader{reader: bytes.NewReader(content), cancel: cancelUpload}
	if err := receiver.Receive(uploadCtx, cancelToken.Bearer, workspace, cancelRepository, cancelReservation.ID, input, cancelledReader); err == nil {
		t.Fatal("cancelled Pub upload succeeded")
	}
	var cancelledStatus string
	var cancelledVerified int
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_pub_reservations WHERE reservation_id = `+p(1), cancelReservation.ID).Scan(&cancelledStatus, &cancelledVerified); err != nil || cancelledStatus != "uploading" || cancelledVerified != 0 {
		t.Fatalf("cancelled Pub upload did not retain its unverified claim: status=%q verified=%d err=%v", cancelledStatus, cancelledVerified, err)
	}
	if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
		t.Fatalf("cancelled Pub upload left staging files: %v", err)
	}
}
