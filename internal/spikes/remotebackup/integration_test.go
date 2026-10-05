//go:build integration

package remotebackup

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"private-registry/internal/spikes/sqlitebackup"
	"private-registry/internal/spikes/testinfra"
)

var fixtureEndpoint, fixtureAccess, fixtureSecret string

func TestMain(m *testing.M) { os.Exit(runIntegration(m)) }

func runIntegration(m *testing.M) (exitCode int) {
	// Floci's explicitly supported local credential pair, never cloud secrets.
	fixtureAccess, fixtureSecret = "test", "test"
	startup, startupCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer startupCancel()
	fixture, err := testinfra.StartFloci(startup)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start isolated Floci (run make setup-floci): %v\n", err)
		return 1
	}
	defer func() {
		if err := fixture.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "cleanup owned Floci container: %v\n", err)
			exitCode = 1
		}
	}()
	fixtureEndpoint = fixture.Endpoint
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 200 * time.Millisecond}
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, fixtureEndpoint+"/health", nil)
		if err != nil {
			return 1
		}
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "isolated Floci did not become ready")
			return 1
		case <-time.After(50 * time.Millisecond):
		}
	}
	return m.Run()
}

func randomID() (string, error) {
	var buffer [16]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer[:]), nil
}

func realStore(t *testing.T) (Store, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	client, err := NewClient(fixtureEndpoint, fixtureAccess, fixtureSecret)
	if err != nil {
		t.Fatal(err)
	}
	id, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	bucket := "spike-" + id
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	return Store{Client: client, Bucket: bucket}, ctx
}

func TestRemoteSQLiteRecoveryWithoutOrigin(t *testing.T) {
	store, ctx := realStore(t)
	directory := t.TempDir()
	source := filepath.Join(directory, "origin.db")
	dsn, err := sqlitebackup.DSN(source)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, `CREATE TABLE owners(id INTEGER PRIMARY KEY);
		CREATE TABLE packages(id INTEGER PRIMARY KEY, owner_id INTEGER REFERENCES owners(id), payload BLOB);
		INSERT INTO owners VALUES(1);
		INSERT INTO packages VALUES(1, 1, zeroblob(16384));`); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(directory, "snapshot.db")
	if _, err := sqlitebackup.Snapshot(ctx, db, snapshot, sqlitebackup.Options{PagesPerStep: 1}); err != nil {
		t.Fatal(err)
	}
	digest, err := sqlitebackup.Digest(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Upload(ctx, snapshot, "backup.age", identity.Recipient(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.PlaintextSHA256 != digest || receipt.Parts < 1 || receipt.CiphertextBytes <= receipt.PlaintextBytes {
		t.Fatalf("invalid upload receipt: %+v", receipt)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{source, snapshot} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, sidecar := range []string{source + "-wal", source + "-shm", snapshot + "-wal", snapshot + "-shm"} {
		if _, err := os.Stat(sidecar); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("origin still available: %s (%v)", sidecar, err)
		}
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := store.Restore(ctx, "backup.age", restored, identity, digest, receipt.PlaintextBytes); err != nil {
		t.Fatal(err)
	}
	actual, err := sqlitebackup.Digest(restored)
	if err != nil || actual != digest {
		t.Fatalf("remote restore digest mismatch: %s %v", actual, err)
	}
	recoveryDSN, err := sqlitebackup.DSN(restored)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := sql.Open("sqlite", recoveryDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer recovery.Close()
	var integrity string
	if err := recovery.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("restore integrity: %s %v", integrity, err)
	}
	var count int
	if err := recovery.QueryRowContext(ctx, "SELECT COUNT(*) FROM packages WHERE owner_id=1").Scan(&count); err != nil || count != 1 {
		t.Fatalf("restored rows: %d %v", count, err)
	}
	rows, err := recovery.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() || rows.Err() != nil {
		t.Fatal("restored foreign keys invalid")
	}
	t.Logf("remote roundtrip: %d plaintext bytes, %d ciphertext bytes, %d part(s), digest/integrity/foreign keys OK; origin removed", receipt.PlaintextBytes, receipt.CiphertextBytes, receipt.Parts)
}

func TestRemoteMultipartAndAbort(t *testing.T) {
	store, ctx := realStore(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "large.bin")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(file, rand.Reader, 2*PartSize+128); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Upload(ctx, path, "large.age", identity.Recipient(), nil)
	if err != nil || receipt.Parts != 3 {
		t.Fatalf("expected three multipart chunks, got %+v (%v)", receipt, err)
	}
	restored := filepath.Join(t.TempDir(), "large.bin")
	if err := store.Restore(ctx, "large.age", restored, identity, receipt.PlaintextSHA256, receipt.PlaintextBytes); err != nil {
		t.Fatal(err)
	}
	for _, cancelUpload := range []bool{false, true} {
		t.Run(map[bool]string{false: "part failure", true: "cancel"}[cancelUpload], func(t *testing.T) {
			operation, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			marker := errors.New("injected observer failure")
			key := fmt.Sprintf("failed-%t.age", cancelUpload)
			_, err := store.Upload(operation, path, key, identity.Recipient(), func(int) error {
				if cancelUpload {
					cancel()
					return nil
				}
				return marker
			})
			if cancelUpload {
				marker = context.Canceled
			}
			if !errors.Is(err, marker) {
				t.Fatalf("expected %v, got %v", marker, err)
			}
			if _, err := store.Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(store.Bucket), Key: aws.String(key)}); err == nil {
				t.Fatal("failed upload exposed a complete object")
			}
			pending, err := store.Client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(store.Bucket)})
			if err != nil || len(pending.Uploads) != 0 {
				t.Fatalf("abandoned parts retained: %+v %v", pending, err)
			}
		})
	}
	before, err := store.Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(store.Bucket), Key: aws.String("large.age")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upload(ctx, path, "large.age", identity.Recipient(), nil); err == nil {
		t.Fatal("existing remote object overwritten")
	}
	after, err := store.Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(store.Bucket), Key: aws.String("large.age")})
	if err != nil || aws.ToString(before.ETag) != aws.ToString(after.ETag) {
		t.Fatal("existing remote object changed")
	}
}

func TestRemoteRejectsCorruptionAndInvalidRecovery(t *testing.T) {
	store, ctx := realStore(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, bytes.Repeat([]byte("private metadata"), 20000), 0o600); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Upload(ctx, path, "valid.age", identity.Recipient(), nil)
	if err != nil {
		t.Fatal(err)
	}
	object, err := store.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(store.Bucket), Key: aws.String("valid.age")})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, readErr := io.ReadAll(object.Body)
	if err := errors.Join(readErr, object.Body.Close()); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("private metadata")) {
		t.Fatal("plaintext exposed in remote object")
	}
	for _, kind := range []string{"wrong key", "tamper", "truncated", "digest", "size", "missing", "canceled", "existing"} {
		t.Run(kind, func(t *testing.T) {
			key, digest, limit := "valid.age", receipt.PlaintextSHA256, receipt.PlaintextBytes
			keyIdentity := identity
			operation, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			output := filepath.Join(t.TempDir(), "restore")
			switch kind {
			case "wrong key":
				keyIdentity = wrong
			case "tamper", "truncated":
				data := bytes.Clone(ciphertext)
				if kind == "tamper" {
					data[len(data)-1] ^= 1
				} else {
					data = data[:len(data)-32]
				}
				key = kind + ".age"
				if _, err := store.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(store.Bucket), Key: aws.String(key), Body: bytes.NewReader(data)}); err != nil {
					t.Fatal(err)
				}
			case "digest":
				digest = strings.Repeat("0", 64)
			case "size":
				limit--
			case "missing":
				key = "missing.age"
			case "canceled":
				cancel()
			case "existing":
				if err := os.WriteFile(output, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.Restore(operation, key, output, keyIdentity, digest, limit); err == nil {
				t.Fatal("invalid recovery accepted")
			}
			if kind == "existing" {
				data, err := os.ReadFile(output)
				if err != nil || string(data) != "keep" {
					t.Fatalf("existing destination changed: %q %v", data, err)
				}
			} else if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial plaintext retained: %v", err)
			}
		})
	}
}

type failingRecipient struct{}

func (failingRecipient) Wrap([]byte) ([]*age.Stanza, error) {
	return nil, io.ErrUnexpectedEOF
}

func TestRemoteRejectsEncryptionFailureAndBadCredentials(t *testing.T) {
	store, ctx := realStore(t)
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("synthetic metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upload(ctx, path, "failed-encryption.age", failingRecipient{}, nil); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("encryption error lost: %v", err)
	}
	if _, err := store.Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(store.Bucket), Key: aws.String("failed-encryption.age")}); err == nil {
		t.Fatal("encryption failure exposed remote content")
	}
	pending, err := store.Client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(store.Bucket)})
	if err != nil || len(pending.Uploads) != 0 {
		t.Fatalf("encryption failure retained multipart parts: %v", err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	badClient, err := NewClient(fixtureEndpoint, fixtureAccess, fixtureSecret+"wrong")
	if err != nil {
		t.Fatal(err)
	}
	badStore := Store{Client: badClient, Bucket: store.Bucket}
	if _, err := badStore.Upload(ctx, path, "bad-auth.age", identity.Recipient(), nil); err == nil {
		t.Fatal("wrong credentials accepted")
	}
	if _, err := store.Upload(ctx, filepath.Join(t.TempDir(), "missing"), "missing-source.age", identity.Recipient(), nil); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing source accepted: %v", err)
	}
}

func TestRemoteUnavailableEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient("http://"+address, "test", "test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	store := Store{Client: client, Bucket: "unavailable-fixture"}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upload(ctx, path, "backup.age", identity.Recipient(), nil); err == nil {
		t.Fatal("unavailable storage accepted an upload")
	}
	recoveryContext, recoveryCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer recoveryCancel()
	output := filepath.Join(t.TempDir(), "restore")
	if err := store.Restore(recoveryContext, "backup.age", output, identity, strings.Repeat("0", 64), 10); err == nil {
		t.Fatal("unavailable storage accepted restore")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unavailable storage created plaintext")
	}
}

// Floci 2.1.0 can admit both conditional completions concurrently. This is a
// capability probe, not an atomicity acceptance test for production storage.
func TestFlociConcurrentConditionalCompletionProbe(t *testing.T) {
	store, ctx := realStore(t)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("synthetic competing snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	var ready sync.WaitGroup
	ready.Add(2)
	release := make(chan struct{})
	go func() { ready.Wait(); close(release) }()
	type outcome struct {
		receipt Receipt
		err     error
	}
	results := make(chan outcome, 2)
	for range 2 {
		go func() {
			arrived := false
			defer func() {
				if !arrived {
					ready.Done()
				}
			}()
			receipt, err := store.Upload(ctx, path, "same.age", identity.Recipient(), func(int) error {
				arrived = true
				ready.Done()
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			results <- outcome{receipt, err}
		}()
	}
	winners := 0
	var winner Receipt
	for range 2 {
		result := <-results
		if result.err == nil {
			winners++
			winner = result.receipt
		} else {
			var apiError interface{ ErrorCode() string }
			if !errors.As(result.err, &apiError) || apiError.ErrorCode() != "PreconditionFailed" {
				t.Fatalf("unexpected competing-upload error: %v", result.err)
			}
			t.Logf("competing upload rejected: %v", result.err)
		}
	}
	if winners < 1 {
		t.Fatal("neither competing fixture upload completed")
	}
	t.Logf("Floci conditional-completion probe: %d winner(s); one-winner atomicity is NOT established on this emulator", winners)
	if err := store.Restore(ctx, "same.age", filepath.Join(t.TempDir(), "restored"), identity, winner.PlaintextSHA256, winner.PlaintextBytes); err != nil {
		t.Fatal(err)
	}
	pending, err := store.Client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(store.Bucket)})
	if err != nil || len(pending.Uploads) != 0 {
		t.Fatalf("competing upload retained incomplete parts: %v", err)
	}
}
