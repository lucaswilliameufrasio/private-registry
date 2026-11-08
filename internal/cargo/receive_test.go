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
	options := cargo.ReceiptOptions{StagingDirectory: staging, Limits: cargo.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxFiles: 100, MaxManifestBytes: 4096}, MaxConcurrent: 1, CurrentIndex: "sparse+https://registry.example/index/", DefaultIndex: "https://github.com/rust-lang/crates.io-index"}
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
	closeErr := object.Close()
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
