package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/google/uuid"
	"private-registry/internal/storage"
)

func TestRestoreReceiptedGenericObjectVerifiesCiphertextBeforeWriting(t *testing.T) {
	ctx := context.Background()
	plain := []byte("synthetic independently receipted object")
	digest := sha256.Sum256(plain)
	key, err := storage.NewObjectKey(uuid.NewString(), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	object := GenericObject{Key: key, Size: int64(len(plain))}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	source := syntheticDriver{body: plain, info: storage.ObjectInfo{Key: key, Size: object.Size}}
	if err := EncryptGenericObject(ctx, source, object, &sealed, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	cipherDigest := sha256.Sum256(sealed.Bytes())
	receipt := ObjectReceipt{Version: 1, InstallationID: uuid.NewString(), BackupID: uuid.NewString(), WorkspaceID: key.WorkspaceID, PlainSHA256: key.SHA256, PlainBytes: object.Size, CipherSHA256: hex.EncodeToString(cipherDigest[:]), CipherBytes: int64(sealed.Len())}
	envelope, err := SignObjectReceipt(receipt, private)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := storage.NewFileSystem(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	stage := func() *os.File {
		t.Helper()
		file, err := os.CreateTemp(t.TempDir(), "stage-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		return file
	}
	modified := bytes.Clone(sealed.Bytes())
	modified[len(modified)-1] ^= 1
	if err := RestoreReceiptedGenericObject(ctx, bytes.NewReader(modified), envelope, public, receipt.InstallationID, receipt.BackupID, identity, stage(), stage(), destination); err == nil {
		t.Fatal("ciphertext differing from the receipt was accepted")
	}
	if reader, _, err := destination.Open(ctx, key); err == nil {
		_ = reader.Close()
		t.Fatal("unverified ciphertext reached destination")
	}
	if err := RestoreReceiptedGenericObject(ctx, bytes.NewReader(sealed.Bytes()), envelope, public, receipt.InstallationID, uuid.NewString(), identity, stage(), stage(), destination); err == nil {
		t.Fatal("wrong backup context was accepted")
	}
	if err := RestoreReceiptedGenericObject(ctx, bytes.NewReader(sealed.Bytes()), envelope, public, receipt.InstallationID, receipt.BackupID, identity, stage(), stage(), destination); err != nil {
		t.Fatal("restore valid receipted object:", err)
	}
	reader, _, err := destination.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, plain) {
		t.Fatalf("read restored object: read=%v close=%v", readErr, closeErr)
	}
}
