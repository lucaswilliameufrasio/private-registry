package cargo_test

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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/backup"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/migrations"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

func TestSQLiteCargoReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DataDir: root, DatabaseDriver: config.SQLite, DatabaseDSN: filepath.Join(root, "registry.sqlite"), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	exerciseCargoReceipt(t, ctx, db, config.SQLite, root)
}

type observingReader struct{ reads int }

func (r *observingReader) Read([]byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

type pausedReceiptReader struct {
	source  io.Reader
	started chan struct{}
	release chan struct{}
	paused  bool
}

type revokeOnReceiptOpen struct {
	storage.Driver
	revoke func() error
	err    error
}

type corruptReceiptReadback struct{ storage.Driver }

func (s corruptReceiptReadback) Open(ctx context.Context, key storage.ObjectKey) (io.ReadCloser, storage.ObjectInfo, error) {
	reader, info, err := s.Driver.Open(ctx, key)
	if err != nil {
		return reader, info, err
	}
	if err := reader.Close(); err != nil {
		return nil, storage.ObjectInfo{}, err
	}
	return io.NopCloser(strings.NewReader("synthetic corrupt readback")), info, nil
}

func (s *revokeOnReceiptOpen) Open(ctx context.Context, key storage.ObjectKey) (io.ReadCloser, storage.ObjectInfo, error) {
	if s.revoke != nil {
		s.err = s.revoke()
		s.revoke = nil
	}
	return s.Driver.Open(ctx, key)
}

func (r *pausedReceiptReader) Read(p []byte) (int, error) {
	if !r.paused {
		r.paused = true
		close(r.started)
		<-r.release
	}
	return r.source.Read(p)
}

func exerciseCargoReceipt(t *testing.T, ctx context.Context, db *sql.DB, driver config.DatabaseDriver, root string) {
	t.Helper()
	bind := func(n int) string {
		if driver == config.Postgres {
			return fmt.Sprintf("$%d", n)
		}
		return "?"
	}
	user, workspace, repository, grant := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	items := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (` + bind(1) + `, 'Synthetic', 'now', 'now')`, []any{user}},
		{`INSERT INTO registry_workspaces (workspace_id, slug, display_name, created_by, created_at) VALUES (` + bind(1) + `, 'receipt-workspace', 'Receipt', ` + bind(2) + `, 'now')`, []any{workspace, user}},
		{`INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, created_by, created_at, updated_at) VALUES (` + bind(1) + `, ` + bind(2) + `, 'owner', ` + bind(3) + `, 'now', 'now')`, []any{workspace, user, user}},
		{`INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format, review_required) VALUES (` + bind(1) + `, ` + bind(2) + `, 'cargo', 'Cargo', ` + bind(3) + `, 'now', 'now', 'cargo', 0)`, []any{repository, workspace, user}},
		{`INSERT INTO registry_repository_grants (grant_id, repository_id, workspace_id, user_id, role, granted_by, granted_at) VALUES (` + bind(1) + `, ` + bind(2) + `, ` + bind(3) + `, ` + bind(4) + `, 'publisher', ` + bind(5) + `, 'now')`, []any{grant, repository, workspace, user, user}},
	}
	for _, item := range items {
		if _, err := db.ExecContext(ctx, item.query, item.args...); err != nil {
			t.Fatal(err)
		}
	}
	repos, err := repositories.New(db, driver)
	if err != nil {
		t.Fatal(err)
	}
	token, err := repos.IssueCargoWriteToken(ctx, user, workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reservations, err := cargo.NewReservationService(db, repos, driver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewFileSystem(filepath.Join(root, "receipt-objects"))
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "receipt-staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	options := cargo.ReceiptOptions{StagingDirectory: staging, Limits: cargo.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxFiles: 100, MaxManifestBytes: 4096}, MaxConcurrent: 1, IndexOrigin: "https://registry.example", DefaultIndex: "https://github.com/rust-lang/crates.io-index"}
	receipts, err := cargo.NewReceiptService(db, repos, driver, store, options)
	if err != nil {
		t.Fatal(err)
	}
	archive := syntheticCrate(t, "1.0.0")
	hash := sha256.Sum256(archive)
	frame := cargo.PublishFrame{Metadata: []byte(`{"name":"receipt_fixture","vers":"1.0.0","deps":[],"features":{}}`), Size: int64(len(archive)), SHA256: hex.EncodeToString(hash[:])}
	reservation, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, frame)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := repos.CargoReviewPolicy(ctx, user, workspace, repository)
	if err != nil || policy.Required {
		t.Fatalf("unexpected initial Cargo review policy: %v", err)
	}
	policy, err = repos.SetCargoReviewPolicy(ctx, user, workspace, repository, policy.Revision, true)
	if err != nil || !policy.Required {
		t.Fatalf("enable Cargo review: %v", err)
	}
	if _, err := repos.SetCargoReviewPolicy(ctx, user, workspace, repository, policy.Revision, false); err != nil {
		t.Fatalf("disable Cargo review: %v", err)
	}
	var reservedHold int
	if err := db.QueryRowContext(ctx, `SELECT review_hold FROM registry_cargo_reservations WHERE reservation_id = `+bind(1), reservation.ID).Scan(&reservedHold); err != nil || reservedHold != 1 {
		t.Fatalf("review hold disappeared after policy change: %v", err)
	}
	reader := &observingReader{}
	if err := receipts.Receive(ctx, "invalid", workspace, repository, reservation.ID, frame, reader); !errors.Is(err, repositories.ErrCargoWriteTokenUnavailable) || reader.reads != 0 {
		t.Fatalf("unauthorized receipt consumed body: reads=%d err=%v", reader.reads, err)
	}
	badFrame := frame
	badFrame.SHA256 = strings.Repeat("a", 64)
	reader = &observingReader{}
	if err := receipts.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, badFrame, reader); !errors.Is(err, cargo.ErrReservationUnavailable) || reader.reads != 0 {
		t.Fatalf("unmatched receipt consumed body: reads=%d err=%v", reader.reads, err)
	}
	if err := receipts.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, frame, bytes.NewReader([]byte("invalid"))); err == nil {
		t.Fatal("invalid archive was accepted")
	}
	var status string
	var verified, hold int
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified, review_hold FROM registry_cargo_reservations WHERE reservation_id = `+bind(1), reservation.ID).Scan(&status, &verified, &hold); err != nil || status != "reserved" || verified != 0 {
		t.Fatalf("failed receipt changed state: %v", err)
	}
	paused := &pausedReceiptReader{source: bytes.NewReader(archive), started: make(chan struct{}), release: make(chan struct{})}
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- receipts.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, frame, paused)
	}()
	select {
	case <-paused.started:
	case <-ctx.Done():
		close(paused.release)
		t.Fatal("Cargo receipt did not start")
	}
	competing := &observingReader{}
	competingErr := receipts.Receive(ctx, token.Bearer, workspace, repository, reservation.ID, frame, competing)
	close(paused.release)
	firstErr := <-firstResult
	if !errors.Is(competingErr, cargo.ErrReceiptCapacity) || competing.reads != 0 {
		t.Fatalf("competing Cargo receipt consumed body: reads=%d err=%v", competing.reads, competingErr)
	}
	if firstErr != nil {
		t.Fatalf("valid Cargo receipt failed: %v", firstErr)
	}
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified, review_hold FROM registry_cargo_reservations WHERE reservation_id = `+bind(1), reservation.ID).Scan(&status, &verified, &hold); err != nil || status != "uploaded" || verified != 1 || hold != 1 {
		t.Fatalf("verified receipt missing or not held for review: %v", err)
	}
	reviewer := uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (`+bind(1)+`, 'Reviewer', 'now', 'now')`, reviewer); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO registry_workspace_memberships (workspace_id, user_id, role, created_by, created_at, updated_at) VALUES (`+bind(1)+`, `+bind(2)+`, 'member', `+bind(3)+`, 'now', 'now')`, workspace, reviewer, user); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace, repository, reservation.ID, "approved", ""); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("review without explicit grant: %v", err)
	}
	if _, _, err := reservations.ListReviewCandidates(ctx, reviewer, workspace, repository, "", 10); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("review candidates visible without reviewer grant: %v", err)
	}
	if reader, _, err := receipts.OpenReviewArchive(ctx, reviewer, workspace, repository, reservation.ID); !errors.Is(err, repositories.ErrForbidden) {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("review archive accessible without reviewer grant: %v", err)
	}
	if _, err := repos.GrantCargoReviewer(ctx, user, workspace, repository, user); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, user, workspace, repository, reservation.ID, "approved", ""); !errors.Is(err, cargo.ErrReviewUnavailable) {
		t.Fatalf("self approval accepted: %v", err)
	}
	if _, err := repos.GrantCargoReviewer(ctx, user, workspace, repository, reviewer); err != nil {
		t.Fatal(err)
	}
	candidates, more, err := reservations.ListReviewCandidates(ctx, reviewer, workspace, repository, "", 10)
	if err != nil || more || len(candidates) != 1 || candidates[0].ID != reservation.ID || candidates[0].Name != "receipt_fixture" || candidates[0].PublisherID != user {
		t.Fatalf("authorized review candidates incorrect: count=%d more=%t err=%v", len(candidates), more, err)
	}
	reviewArchive, reviewSize, err := receipts.OpenReviewArchive(ctx, reviewer, workspace, repository, reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	reviewBytes, readErr := io.ReadAll(reviewArchive)
	closeErr := reviewArchive.Close()
	if readErr != nil || closeErr != nil || reviewSize != int64(len(archive)) || !bytes.Equal(reviewBytes, archive) {
		t.Fatal("authorized reviewer did not receive the verified archive")
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_cargo_review_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'cargo.review.approved' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := reservations.DecideReview(ctx, reviewer, workspace, repository, reservation.ID, "approved", ""); err == nil {
			t.Fatal("review approval succeeded without audit")
		}
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_cargo_review_decisions WHERE reservation_id = ?`, reservation.ID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed review audit left a decision: count=%d err=%v", count, err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_cargo_review_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	decision, err := reservations.DecideReview(ctx, reviewer, workspace, repository, reservation.ID, "approved", "")
	if err != nil || decision == "" {
		t.Fatalf("review approval failed: %v", err)
	}
	type reviewResult struct {
		id  string
		err error
	}
	results := make(chan reviewResult, 2)
	for range 2 {
		go func() {
			id, err := reservations.DecideReview(ctx, reviewer, workspace, repository, reservation.ID, "approved", "")
			results <- reviewResult{id: id, err: err}
		}()
	}
	for range 2 {
		result := <-results
		if result.err != nil || result.id != decision {
			t.Fatalf("concurrent approval retry did not reconcile: %v", result.err)
		}
	}
	var decisionCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_cargo_review_decisions WHERE reservation_id = `+bind(1), reservation.ID).Scan(&decisionCount); err != nil || decisionCount != 1 {
		t.Fatalf("concurrent retries created duplicate decisions: count=%d err=%v", decisionCount, err)
	}
	checkApproval := func() error {
		return repos.WithCargoWriteTokenTransaction(ctx, token.Bearer, workspace, repository, func(tx *sql.Tx, publisher string) error {
			return reservations.RequireCurrentApproval(ctx, tx, workspace, repository, reservation.ID, publisher)
		})
	}
	if err := checkApproval(); err != nil {
		t.Fatalf("current approval rejected: %v", err)
	}
	if err := repos.RevokeCargoReviewer(ctx, user, workspace, repository, reviewer); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantCargoReviewer(ctx, user, workspace, repository, reviewer); err != nil {
		t.Fatal(err)
	}
	if err := checkApproval(); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("reviewer regrant revived approval: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace, repository, reservation.ID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	if err := checkApproval(); err != nil {
		t.Fatalf("new approval rejected: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_users SET status = 'suspended' WHERE user_id = `+bind(1), reviewer); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_users SET status = 'active' WHERE user_id = `+bind(1), reviewer); err != nil {
		t.Fatal(err)
	}
	if _, err := repos.GrantCargoReviewer(ctx, user, workspace, repository, reviewer); err != nil {
		t.Fatal(err)
	}
	if err := checkApproval(); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("reviewer reactivation revived approval: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace, repository, reservation.ID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	policy, err = repos.CargoReviewPolicy(ctx, user, workspace, repository)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repos.SetCargoReviewPolicy(ctx, user, workspace, repository, policy.Revision, true); err != nil {
		t.Fatal(err)
	}
	if err := checkApproval(); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("policy change did not invalidate approval: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace, repository, reservation.ID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace, repository, reservation.ID, "rejected", "synthetic rejection"); err != nil {
		t.Fatal(err)
	}
	candidates, more, err = reservations.ListReviewCandidates(ctx, reviewer, workspace, repository, "", 10)
	if err != nil || more || len(candidates) != 0 {
		t.Fatalf("rejected receipt remained a candidate: count=%d more=%t err=%v", len(candidates), more, err)
	}
	if reader, _, err := receipts.OpenReviewArchive(ctx, reviewer, workspace, repository, reservation.ID); !errors.Is(err, cargo.ErrReviewUnavailable) {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("rejected review archive remained accessible: %v", err)
	}
	if err := checkApproval(); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("rejection did not supersede approval: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace, repository, reservation.ID, "approved", ""); !errors.Is(err, cargo.ErrReviewUnavailable) {
		t.Fatalf("terminal rejection was overridden: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_review_decisions SET decision = 'rejected' WHERE decision_id = `+bind(1), decision); err == nil {
		t.Fatal("review decision was mutable")
	}
	policy, err = repos.CargoReviewPolicy(ctx, user, workspace, repository)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repos.SetCargoReviewPolicy(ctx, user, workspace, repository, policy.Revision, false); err != nil {
		t.Fatal(err)
	}
	var published int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_cargo_versions WHERE repository_id = `+bind(1), repository).Scan(&published); err != nil || published != 0 {
		t.Fatalf("receipt became published: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET index_entry = '{}' WHERE reservation_id = `+bind(1), reservation.ID); err == nil {
		t.Fatal("verified receipt metadata was modified")
	}
	key, err := storage.NewObjectKey(workspace, frame.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	object, _, err := store.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	readback, readErr := io.ReadAll(object)
	closeErr = object.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(readback, archive) {
		t.Fatal("verified object readback differs")
	}
	entries, err := os.ReadDir(staging)
	if err != nil || len(entries) != 0 {
		t.Fatal("receipt staging was not cleaned")
	}
	secondToken, err := repos.IssueCargoWriteToken(ctx, user, workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	secondArchive := syntheticCrate(t, "1.0.1")
	secondDigest := sha256.Sum256(secondArchive)
	secondFrame := cargo.PublishFrame{Metadata: []byte(`{"name":"receipt_fixture","vers":"1.0.1","deps":[],"features":{}}`), Size: int64(len(secondArchive)), SHA256: hex.EncodeToString(secondDigest[:])}
	secondReservation, err := reservations.Reserve(ctx, secondToken.Bearer, workspace, repository, secondFrame)
	if err != nil {
		t.Fatal(err)
	}
	revokingStore := &revokeOnReceiptOpen{Driver: store, revoke: func() error { return repos.RevokeCargoWriteToken(ctx, user, secondToken.ID) }}
	revokingReceipts, err := cargo.NewReceiptService(db, repos, driver, revokingStore, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := revokingReceipts.Receive(ctx, secondToken.Bearer, workspace, repository, secondReservation.ID, secondFrame, bytes.NewReader(secondArchive)); !errors.Is(err, repositories.ErrCargoWriteTokenUnavailable) || revokingStore.err != nil {
		t.Fatalf("revocation during readback did not prevent receipt: err=%v revoke=%v", err, revokingStore.err)
	}
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_cargo_reservations WHERE reservation_id = `+bind(1), secondReservation.ID).Scan(&status, &verified); err != nil || status != "reserved" || verified != 0 {
		t.Fatalf("revoked receipt became visible: %v", err)
	}
	if driver == config.SQLite {
		thirdArchive := syntheticCrate(t, "1.0.2")
		thirdDigest := sha256.Sum256(thirdArchive)
		thirdFrame := cargo.PublishFrame{Metadata: []byte(`{"name":"receipt_fixture","vers":"1.0.2","deps":[],"features":{}}`), Size: int64(len(thirdArchive)), SHA256: hex.EncodeToString(thirdDigest[:])}
		thirdReservation, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, thirdFrame)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_cargo_receipt_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'cargo.receipt.created' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if err := receipts.Receive(ctx, token.Bearer, workspace, repository, thirdReservation.ID, thirdFrame, bytes.NewReader(thirdArchive)); err == nil {
			t.Fatal("Cargo receipt succeeded without audit")
		}
		if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_cargo_reservations WHERE reservation_id = ?`, thirdReservation.ID).Scan(&status, &verified); err != nil || status != "reserved" || verified != 0 {
			t.Fatalf("failed audit changed Cargo receipt: %v", err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_cargo_receipt_audit_failure`); err != nil {
			t.Fatal(err)
		}
		if err := receipts.Receive(ctx, token.Bearer, workspace, repository, thirdReservation.ID, thirdFrame, bytes.NewReader(thirdArchive)); err != nil {
			t.Fatalf("Cargo receipt retry after failed audit: %v", err)
		}
	}
	corruptArchive := syntheticCrate(t, "1.0.3")
	corruptDigest := sha256.Sum256(corruptArchive)
	corruptFrame := cargo.PublishFrame{Metadata: []byte(`{"name":"receipt_fixture","vers":"1.0.3","deps":[],"features":{}}`), Size: int64(len(corruptArchive)), SHA256: hex.EncodeToString(corruptDigest[:])}
	corruptReservation, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, corruptFrame)
	if err != nil {
		t.Fatal(err)
	}
	corruptReceipts, err := cargo.NewReceiptService(db, repos, driver, corruptReceiptReadback{Driver: store}, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := corruptReceipts.Receive(ctx, token.Bearer, workspace, repository, corruptReservation.ID, corruptFrame, bytes.NewReader(corruptArchive)); err == nil {
		t.Fatal("corrupt object readback was accepted")
	}
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_cargo_reservations WHERE reservation_id = `+bind(1), corruptReservation.ID).Scan(&status, &verified); err != nil || status != "reserved" || verified != 0 {
		t.Fatalf("corrupt object readback created a receipt: %v", err)
	}
	expiringArchive := syntheticCrate(t, "1.0.4")
	expiringDigest := sha256.Sum256(expiringArchive)
	expiringFrame := cargo.PublishFrame{Metadata: []byte(`{"name":"receipt_fixture","vers":"1.0.4","deps":[],"features":{}}`), Size: int64(len(expiringArchive)), SHA256: hex.EncodeToString(expiringDigest[:])}
	expiringReservation, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, expiringFrame)
	if err != nil {
		t.Fatal(err)
	}
	expiringReader := &pausedReceiptReader{source: bytes.NewReader(expiringArchive), started: make(chan struct{}), release: make(chan struct{})}
	expiringResult := make(chan error, 1)
	go func() {
		expiringResult <- receipts.Receive(ctx, token.Bearer, workspace, repository, expiringReservation.ID, expiringFrame, expiringReader)
	}()
	select {
	case <-expiringReader.started:
	case <-ctx.Done():
		close(expiringReader.release)
		t.Fatal("expiring Cargo receipt did not start")
	}
	policy, err = repos.CargoReviewPolicy(ctx, user, workspace, repository)
	if err != nil || policy.Required {
		close(expiringReader.release)
		<-expiringResult
		t.Fatalf("unexpected review policy before toggle: %v", err)
	}
	policy, err = repos.SetCargoReviewPolicy(ctx, user, workspace, repository, policy.Revision, true)
	if err != nil {
		close(expiringReader.release)
		<-expiringResult
		t.Fatal(err)
	}
	if _, err := repos.SetCargoReviewPolicy(ctx, user, workspace, repository, policy.Revision, false); err != nil {
		close(expiringReader.release)
		<-expiringResult
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT review_hold FROM registry_cargo_reservations WHERE reservation_id = `+bind(1), expiringReservation.ID).Scan(&hold); err != nil || hold != 1 {
		close(expiringReader.release)
		<-expiringResult
		t.Fatalf("in-flight Cargo review hold disappeared: %v", err)
	}
	if _, err := reservations.ExpireUploadBatch(ctx, time.Now().UTC().Add(48*time.Hour), 100); err != nil {
		close(expiringReader.release)
		<-expiringResult
		t.Fatal(err)
	}
	close(expiringReader.release)
	if err := <-expiringResult; !errors.Is(err, cargo.ErrReservationUnavailable) {
		t.Fatalf("expired claim produced a receipt: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_cargo_reservations WHERE reservation_id = `+bind(1), expiringReservation.ID).Scan(&status, &verified); err != nil || status != "expired" || verified != 0 {
		t.Fatalf("expired claim was reactivated: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT status, object_verified FROM registry_cargo_reservations WHERE reservation_id = `+bind(1), reservation.ID).Scan(&status, &verified); err != nil || status != "uploaded" || verified != 1 {
		t.Fatalf("verified receipt was expired: %v", err)
	}
	policy, err = repos.CargoReviewPolicy(ctx, user, workspace, repository)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repos.SetCargoReviewPolicy(ctx, user, workspace, repository, policy.Revision, true); err != nil {
		t.Fatal(err)
	}
	lastArchive := syntheticCrate(t, "1.0.5")
	lastDigest := sha256.Sum256(lastArchive)
	lastFrame := cargo.PublishFrame{Metadata: []byte(`{"name":"receipt_fixture","vers":"1.0.5","deps":[],"features":{}}`), Size: int64(len(lastArchive)), SHA256: hex.EncodeToString(lastDigest[:])}
	lastReservation, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, lastFrame)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.Receive(ctx, token.Bearer, workspace, repository, lastReservation.ID, lastFrame, bytes.NewReader(lastArchive)); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.ReadSparseIndex(ctx, user, workspace, repository, "receipt_fixture"); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("Cargo index accessible without reader grant: %v", err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, user, workspace, repository, user, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.ReadSparseIndex(ctx, user, workspace, repository, "receipt_fixture"); !errors.Is(err, cargo.ErrPackageUnavailable) {
		t.Fatalf("pending Cargo receipt appeared in index: %v", err)
	}
	if reader, _, err := receipts.OpenPublishedArchive(ctx, user, workspace, repository, "receipt_fixture", "1.0.5"); !errors.Is(err, cargo.ErrPackageUnavailable) {
		if reader != nil {
			_ = reader.Close()
		}
		t.Fatalf("pending Cargo archive was accessible: %v", err)
	}
	if _, err := reservations.PublishReceipt(ctx, token.Bearer, workspace, repository, lastReservation.ID); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("publication without review accepted: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace, repository, lastReservation.ID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	policy, err = repos.CargoReviewPolicy(ctx, user, workspace, repository)
	if err != nil {
		t.Fatal(err)
	}
	policy, err = repos.SetCargoReviewPolicy(ctx, user, workspace, repository, policy.Revision, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.PublishReceipt(ctx, token.Bearer, workspace, repository, lastReservation.ID); !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("publication accepted approval for an old policy: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace, repository, lastReservation.ID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	var usedBefore int64
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(SUM(archive_size), 0) FROM registry_cargo_reservations WHERE workspace_id = `+bind(1)+` AND status IN ('reserved', 'uploading', 'uploaded')`, workspace).Scan(&usedBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_workspaces SET logical_quota_bytes = `+bind(1)+` WHERE workspace_id = `+bind(2), usedBefore, workspace); err != nil {
		t.Fatal(err)
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_cargo_publish_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'cargo.publication.created' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if _, err := reservations.PublishReceipt(ctx, token.Bearer, workspace, repository, lastReservation.ID); err == nil {
			t.Fatal("publication succeeded without audit")
		}
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_cargo_versions WHERE repository_id = ?`, repository).Scan(&count); err != nil || count != 0 {
			t.Fatalf("failed audit left a published version: count=%d err=%v", count, err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_cargo_publish_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	publicationResults := make(chan reviewResult, 2)
	for range 2 {
		go func() {
			id, err := reservations.PublishReceipt(ctx, token.Bearer, workspace, repository, lastReservation.ID)
			publicationResults <- reviewResult{id: id, err: err}
		}()
	}
	firstPublication, secondPublication := <-publicationResults, <-publicationResults
	publishedID := firstPublication.id
	if firstPublication.err != nil || secondPublication.err != nil || publishedID == "" || secondPublication.id != publishedID {
		t.Fatalf("concurrent Cargo publication did not reconcile: first=%v second=%v", firstPublication.err, secondPublication.err)
	}
	var publishedCount, publicationAuditCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_cargo_versions WHERE repository_id = `+bind(1), repository).Scan(&publishedCount); err != nil || publishedCount != 1 {
		t.Fatalf("concurrent publication created duplicate versions: count=%d err=%v", publishedCount, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events WHERE action = 'cargo.publication.created' AND target_id = `+bind(1), publishedID).Scan(&publicationAuditCount); err != nil || publicationAuditCount != 1 {
		t.Fatalf("publication audit not recorded exactly once: count=%d err=%v", publicationAuditCount, err)
	}
	snapshot, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	inventory, inventoryErr := backup.InventoryCargo(ctx, snapshot, 100, 100)
	if inventoryErr != nil {
		_ = snapshot.Rollback()
		t.Fatal(inventoryErr)
	}
	var publishedReferences int
	for _, object := range inventory {
		if object.Key.WorkspaceID == workspace && object.Key.SHA256 == lastFrame.SHA256 && object.Size == lastFrame.Size {
			publishedReferences++
		}
	}
	if publishedReferences != 1 {
		_ = snapshot.Rollback()
		t.Fatalf("Cargo inventory did not deduplicate published receipt: count=%d", publishedReferences)
	}
	if _, err := backup.InventoryCargo(ctx, snapshot, 100, 1); err == nil {
		_ = snapshot.Rollback()
		t.Fatal("Cargo inventory accepted a reference limit below the snapshot")
	}
	if _, err := backup.InventoryCargo(ctx, snapshot, 1, 100); err == nil {
		_ = snapshot.Rollback()
		t.Fatal("Cargo inventory accepted an object limit below the snapshot")
	}
	if err := snapshot.Rollback(); err != nil {
		t.Fatal(err)
	}
	conflictTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var inventoryPackage string
	if err := conflictTx.QueryRowContext(ctx, `SELECT package_id FROM registry_cargo_versions WHERE cargo_version_id = `+bind(1), publishedID).Scan(&inventoryPackage); err != nil {
		_ = conflictTx.Rollback()
		t.Fatal(err)
	}
	conflictQuery := `INSERT INTO registry_cargo_versions (cargo_version_id, workspace_id, repository_id, package_id, version, version_identity, index_entry, archive_sha256, archive_size, created_by, created_at) VALUES (` + bind(1) + `, ` + bind(2) + `, ` + bind(3) + `, ` + bind(4) + `, '8.8.8', '8.8.8', '{}', ` + bind(5) + `, ` + bind(6) + `, ` + bind(7) + `, 'now')`
	if _, err := conflictTx.ExecContext(ctx, conflictQuery, uuid.NewString(), workspace, repository, inventoryPackage, lastFrame.SHA256, lastFrame.Size+1, user); err != nil {
		_ = conflictTx.Rollback()
		t.Fatal(err)
	}
	if _, err := backup.InventoryCargo(ctx, conflictTx, 100, 100); err == nil {
		_ = conflictTx.Rollback()
		t.Fatal("Cargo inventory accepted conflicting sizes for one object")
	}
	if err := conflictTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM registry_cargo_publications WHERE reservation_id = `+bind(1), lastReservation.ID); err == nil {
		t.Fatal("published receipt linkage was deleted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_publications SET cargo_version_id = cargo_version_id WHERE reservation_id = `+bind(1), lastReservation.ID); err == nil {
		t.Fatal("published receipt linkage was updated")
	}
	if again, err := reservations.PublishReceipt(ctx, token.Bearer, workspace, repository, lastReservation.ID); err != nil || again != publishedID {
		t.Fatalf("publication retry did not reconcile: %v", err)
	}
	index, err := reservations.ReadSparseIndex(ctx, user, workspace, repository, "receipt_fixture")
	if err != nil || !bytes.Contains(index, []byte(`"vers":"1.0.5"`)) || bytes.Contains(index, []byte(`"vers":"1.0.0"`)) {
		t.Fatalf("published Cargo sparse index incorrect: %v", err)
	}
	publishedArchive, publishedSize, err := receipts.OpenPublishedArchive(ctx, user, workspace, repository, "receipt_fixture", "1.0.5")
	if err != nil {
		t.Fatal(err)
	}
	publishedBytes, err := io.ReadAll(publishedArchive)
	publishedCloseErr := publishedArchive.Close()
	if err != nil || publishedCloseErr != nil || publishedSize != int64(len(lastArchive)) || !bytes.Equal(publishedBytes, lastArchive) {
		t.Fatal("published Cargo archive differs from receipt")
	}
	if driver == config.SQLite {
		if _, err := db.ExecContext(ctx, `CREATE TRIGGER synthetic_cargo_yank_audit_failure BEFORE INSERT ON registry_audit_events WHEN NEW.action = 'cargo.version.yanked' BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END`); err != nil {
			t.Fatal(err)
		}
		if err := reservations.SetYanked(ctx, token.Bearer, workspace, repository, "receipt_fixture", "1.0.5", true); err == nil {
			t.Fatal("Cargo yank succeeded without audit")
		}
		var state int
		if err := db.QueryRowContext(ctx, `SELECT yanked FROM registry_cargo_versions WHERE cargo_version_id = ?`, publishedID).Scan(&state); err != nil || state != 0 {
			t.Fatalf("failed yank audit changed state: %v", err)
		}
		if _, err := db.ExecContext(ctx, `DROP TRIGGER synthetic_cargo_yank_audit_failure`); err != nil {
			t.Fatal(err)
		}
	}
	if err := reservations.SetYanked(ctx, token.Bearer, workspace, repository, "receipt_fixture", "1.0.5", true); err != nil {
		t.Fatalf("yank Cargo version: %v", err)
	}
	if err := reservations.SetYanked(ctx, token.Bearer, workspace, repository, "receipt_fixture", "1.0.5", true); err != nil {
		t.Fatalf("repeat Cargo yank: %v", err)
	}
	index, err = reservations.ReadSparseIndex(ctx, user, workspace, repository, "receipt_fixture")
	if err != nil || !bytes.Contains(index, []byte(`"yanked":true`)) {
		t.Fatalf("yank not reflected in Cargo index: %v", err)
	}
	yankedArchive, _, err := receipts.OpenPublishedArchive(ctx, user, workspace, repository, "receipt_fixture", "1.0.5")
	if err != nil {
		t.Fatalf("yanked archive inaccessible to existing lockfile: %v", err)
	}
	if err := yankedArchive.Close(); err != nil {
		t.Fatal(err)
	}
	var yankAudits int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM registry_audit_events WHERE action = 'cargo.version.yanked' AND target_id = `+bind(1), publishedID).Scan(&yankAudits); err != nil || yankAudits != 1 {
		t.Fatalf("Cargo yank audit count=%d err=%v", yankAudits, err)
	}
	if err := reservations.SetYanked(ctx, token.Bearer, workspace, repository, "receipt_fixture", "1.0.5", false); err != nil {
		t.Fatalf("unyank Cargo version: %v", err)
	}
	index, err = reservations.ReadSparseIndex(ctx, user, workspace, repository, "receipt_fixture")
	if err != nil || !bytes.Contains(index, []byte(`"yanked":false`)) {
		t.Fatalf("unyank not reflected in Cargo index: %v", err)
	}
	if err := repos.RevokeRepositoryRole(ctx, user, workspace, repository, user, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.ReadSparseIndex(ctx, user, workspace, repository, "receipt_fixture"); !errors.Is(err, repositories.ErrForbidden) {
		t.Fatalf("Cargo index remained accessible after reader revocation: %v", err)
	}
	quotaFrame := cargo.PublishFrame{Metadata: []byte(`{"name":"quota_after_publish","vers":"1.0.0","deps":[],"features":{}}`), Size: 1, SHA256: strings.Repeat("d", 64)}
	if _, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, quotaFrame); !errors.Is(err, cargo.ErrReservationQuota) {
		t.Fatalf("published version was not counted exactly once at quota: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_workspaces SET logical_quota_bytes = `+bind(1)+` WHERE workspace_id = `+bind(2), usedBefore+1, workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, quotaFrame); err != nil {
		t.Fatalf("publication double-counted receipt bytes: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_workspaces SET logical_quota_bytes = NULL WHERE workspace_id = `+bind(1), workspace); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace, repository, lastReservation.ID, "rejected", "late rejection"); !errors.Is(err, cargo.ErrReviewUnavailable) {
		t.Fatalf("published receipt accepted new review decision: %v", err)
	}
	candidates, _, err = reservations.ListReviewCandidates(ctx, reviewer, workspace, repository, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		if candidate.ID == lastReservation.ID {
			t.Fatal("published receipt remained a review candidate")
		}
	}
	if _, err := repos.SetCargoReviewPolicy(ctx, user, workspace, repository, policy.Revision, true); err != nil {
		t.Fatal(err)
	}
	if again, err := reservations.PublishReceipt(ctx, token.Bearer, workspace, repository, lastReservation.ID); err != nil || again != publishedID {
		t.Fatalf("published retry failed after later policy revision: %v", err)
	}
	raceArchive := syntheticCrate(t, "1.0.6")
	raceDigest := sha256.Sum256(raceArchive)
	raceFrame := cargo.PublishFrame{Metadata: []byte(`{"name":"receipt_fixture","vers":"1.0.6","deps":[],"features":{}}`), Size: int64(len(raceArchive)), SHA256: hex.EncodeToString(raceDigest[:])}
	raceReservation, err := reservations.Reserve(ctx, token.Bearer, workspace, repository, raceFrame)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.Receive(ctx, token.Bearer, workspace, repository, raceReservation.ID, raceFrame, bytes.NewReader(raceArchive)); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var packageID string
	if err := tx.QueryRowContext(ctx, `SELECT package_id FROM registry_cargo_versions WHERE cargo_version_id = `+bind(1), publishedID).Scan(&packageID); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	fakeVersion := uuid.NewString()
	query := `INSERT INTO registry_cargo_versions (cargo_version_id, workspace_id, repository_id, package_id, version, version_identity, index_entry, archive_sha256, archive_size, created_by, created_at) VALUES (` + bind(1) + `, ` + bind(2) + `, ` + bind(3) + `, ` + bind(4) + `, '9.9.9', '9.9.9', '{}', ` + bind(5) + `, 1, ` + bind(6) + `, 'now')`
	if _, err := tx.ExecContext(ctx, query, fakeVersion, workspace, repository, packageID, strings.Repeat("a", 64), user); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	query = `INSERT INTO registry_cargo_publications (reservation_id, cargo_version_id, workspace_id, repository_id) VALUES (` + bind(1) + `, ` + bind(2) + `, ` + bind(3) + `, ` + bind(4) + `)`
	if _, err := tx.ExecContext(ctx, query, raceReservation.ID, fakeVersion, workspace, repository); err == nil {
		_ = tx.Rollback()
		t.Fatal("Cargo publication linked mismatched receipt and version")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	raceResults := make(chan reviewResult, 2)
	go func() {
		id, err := reservations.DecideReview(ctx, reviewer, workspace, repository, raceReservation.ID, "approved", "")
		raceResults <- reviewResult{id: id, err: err}
	}()
	go func() {
		id, err := reservations.DecideReview(ctx, reviewer, workspace, repository, raceReservation.ID, "rejected", "synthetic concurrent rejection")
		raceResults <- reviewResult{id: id, err: err}
	}()
	for range 2 {
		result := <-raceResults
		if result.err != nil && !errors.Is(result.err, cargo.ErrReviewUnavailable) {
			t.Fatalf("unexpected concurrent review result: %v", result.err)
		}
	}
	var lastDecision string
	if err := db.QueryRowContext(ctx, `SELECT decision FROM registry_cargo_review_decisions WHERE reservation_id = `+bind(1)+` ORDER BY decision_sequence DESC LIMIT 1`, raceReservation.ID).Scan(&lastDecision); err != nil || lastDecision != "rejected" {
		t.Fatalf("concurrent rejection was not terminal: decision=%q err=%v", lastDecision, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE registry_cargo_reservations SET recovery_invalidated = 1 WHERE reservation_id = `+bind(1), raceReservation.ID); err != nil {
		t.Fatal(err)
	}
	err = repos.WithCargoWriteTokenTransaction(ctx, token.Bearer, workspace, repository, func(tx *sql.Tx, publisher string) error {
		return reservations.RequireCurrentApproval(ctx, tx, workspace, repository, raceReservation.ID, publisher)
	})
	if !errors.Is(err, cargo.ErrReviewUnavailable) {
		t.Fatalf("recovery-invalidated receipt remained reviewable: %v", err)
	}
	if err := repos.RevokeRepositoryRole(ctx, user, workspace, repository, user, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.PublishReceipt(ctx, token.Bearer, workspace, repository, lastReservation.ID); !errors.Is(err, repositories.ErrCargoWriteTokenUnavailable) {
		t.Fatalf("publication retry accepted revoked publisher grant: %v", err)
	}
	if err := reservations.SetYanked(ctx, token.Bearer, workspace, repository, "receipt_fixture", "1.0.5", true); !errors.Is(err, repositories.ErrCargoWriteTokenUnavailable) {
		t.Fatalf("Cargo yank accepted revoked publisher grant: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace, repository, lastReservation.ID, "approved", ""); !errors.Is(err, cargo.ErrReviewUnavailable) {
		t.Fatalf("approval retry accepted revoked publisher grant: %v", err)
	}
	if _, err := repos.GrantRepositoryRole(ctx, user, workspace, repository, user, repositories.GrantPublisher); err != nil {
		t.Fatal(err)
	}
	newToken, err := repos.IssueCargoWriteToken(ctx, user, workspace, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	err = repos.WithCargoWriteTokenTransaction(ctx, newToken.Bearer, workspace, repository, func(tx *sql.Tx, publisher string) error {
		return reservations.RequireCurrentApproval(ctx, tx, workspace, repository, lastReservation.ID, publisher)
	})
	if !errors.Is(err, repositories.ErrReviewRequired) {
		t.Fatalf("publisher regrant revived approval: %v", err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace, repository, lastReservation.ID, "approved", ""); !errors.Is(err, cargo.ErrReviewUnavailable) {
		t.Fatalf("review accepted receipt bound to old publisher grant: %v", err)
	}
}

func syntheticCrate(t *testing.T, version string) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	manifest := []byte(fmt.Sprintf("[package]\nname = \"receipt_fixture\"\nversion = %q\n", version))
	if err := tw.WriteHeader(&tar.Header{Name: "receipt_fixture-" + version + "/Cargo.toml", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
