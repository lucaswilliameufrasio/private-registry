//go:build integration

package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"private-registry/internal/spikes/remotebackup"
	"private-registry/internal/spikes/testinfra"
	"private-registry/internal/storage"
)

func TestRemoteGenericSetRecoveryFromIsolatedFloci(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	fixture, err := testinfra.StartFloci(ctx)
	if err != nil {
		t.Fatal("start owned Floci:", err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Error("stop owned Floci:", err)
		}
	})
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, fixture.Endpoint+"/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("Floci did not become ready")
		case <-time.After(50 * time.Millisecond):
		}
	}
	client, err := remotebackup.NewClient(fixture.Endpoint, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	bucket := "synthetic-" + uuid.NewString()
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal("create isolated fixture bucket:", err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	installationID, backupID, workspace := uuid.NewString(), uuid.NewString(), uuid.NewString()
	payload := []byte("synthetic remote recovery bytes")
	plainHash := sha256.Sum256(payload)
	key := storage.ObjectKey{WorkspaceID: workspace, SHA256: hex.EncodeToString(plainHash[:])}
	object := GenericObject{Key: key, Size: int64(len(payload))}
	var encrypted bytes.Buffer
	if err := EncryptGenericObject(ctx, syntheticDriver{body: payload, info: storage.ObjectInfo{Key: key, Size: object.Size}}, object, &encrypted, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	remoteKey := "fixture/ciphertext"
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(remoteKey), Body: bytes.NewReader(encrypted.Bytes()), IfNoneMatch: aws.String("*")}); err != nil {
		t.Fatal("upload synthetic ciphertext:", err)
	}
	cipherHash := sha256.Sum256(encrypted.Bytes())
	receipt := ObjectReceipt{Version: 1, InstallationID: installationID, BackupID: backupID, WorkspaceID: workspace, PlainSHA256: key.SHA256, PlainBytes: object.Size, CipherSHA256: hex.EncodeToString(cipherHash[:]), CipherBytes: int64(encrypted.Len())}
	envelope, err := SignObjectReceipt(receipt, private)
	if err != nil {
		t.Fatal(err)
	}
	snapshotHash := sha256.Sum256([]byte("synthetic snapshot"))
	trusted := GenericSetRecovery{Signer: public, InstallationID: installationID, BackupID: backupID, SnapshotSHA256: hex.EncodeToString(snapshotHash[:]), Inventory: []GenericObject{object}}
	setEnvelope, err := SignGenericSet(GenericSet{Version: 1, InstallationID: installationID, BackupID: backupID, SnapshotSHA256: trusted.SnapshotSHA256, Objects: []ObjectReceipt{receipt}}, private)
	if err != nil {
		t.Fatal(err)
	}
	sources := []RecoveryObjectSource{{Receipt: envelope, Open: func(ctx context.Context) (io.ReadCloser, error) {
		result, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(remoteKey)})
		if err != nil {
			return nil, err
		}
		return result.Body, nil
	}}}
	root := t.TempDir()
	destination, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(root, "stage")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	newStage := func() (RecoveryStage, error) {
		file, err := os.CreateTemp(stageDir, "owned-*")
		if err != nil {
			return nil, err
		}
		return testRecoveryStage{File: file}, nil
	}
	missing := []RecoveryObjectSource{{Receipt: envelope, Open: func(ctx context.Context) (io.ReadCloser, error) {
		result, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String("fixture/missing")})
		if err != nil {
			return nil, err
		}
		return result.Body, nil
	}}}
	if err := RestoreGenericSet(ctx, setEnvelope, trusted, missing, identity, newStage, destination); err == nil {
		t.Fatal("missing remote ciphertext was accepted")
	}
	if reader, _, err := destination.Open(ctx, key); err == nil {
		_ = reader.Close()
		t.Fatal("missing remote ciphertext produced a destination object")
	}
	if err := RestoreGenericSet(ctx, setEnvelope, trusted, sources, identity, newStage, destination); err != nil {
		t.Fatal("recover synthetic remote set:", err)
	}
	reader, _, err := destination.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	actual, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(actual, payload) {
		t.Fatalf("verify isolated restored object read=%v close=%v", readErr, closeErr)
	}
	remoteStore, err := storage.NewS3(client, bucket, "capture", filepath.Join(root, "s3-staging"), 4096)
	if err != nil {
		t.Fatal("create experimental fixture storage:", err)
	}
	captured, err := CaptureGenericSet(ctx, trusted, syntheticDriver{body: payload, info: storage.ObjectInfo{Key: key, Size: object.Size}}, remoteStore, identity.Recipient(), private, 4096, newStage)
	if err != nil || len(captured.Receipts) != 1 {
		t.Fatalf("capture isolated remote set receipts=%d error=%v", len(captured.Receipts), err)
	}
	capturedReceipt, err := VerifyObjectReceipt(captured.Receipts[0], public, installationID, backupID)
	if err != nil {
		t.Fatal(err)
	}
	cipherKey := storage.ObjectKey{WorkspaceID: workspace, SHA256: capturedReceipt.CipherSHA256}
	capturedSources := []RecoveryObjectSource{{Receipt: captured.Receipts[0], Open: func(ctx context.Context) (io.ReadCloser, error) {
		reader, _, err := remoteStore.Open(ctx, cipherKey)
		return reader, err
	}}}
	capturedDestination, err := storage.NewFileSystem(filepath.Join(root, "captured-restore"))
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreGenericSet(ctx, captured.Set, trusted, capturedSources, identity, newStage, capturedDestination); err != nil {
		t.Fatal("recover captured Floci object:", err)
	}
	var capturedBytes bytes.Buffer
	if err := CopyGenericObject(ctx, capturedDestination, object, &capturedBytes); err != nil || !bytes.Equal(capturedBytes.Bytes(), payload) {
		t.Fatalf("verify captured remote recovery: %v", err)
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("owned staging remains entries=%d error=%v", len(entries), err)
	}
}
