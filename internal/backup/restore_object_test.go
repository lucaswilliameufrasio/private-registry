package backup

import (
	"bytes"
	"context"
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

func TestRestoreGenericObjectAuthenticatesBeforeDestinationWrite(t *testing.T) {
	ctx := context.Background()
	payload := []byte("synthetic isolated restore")
	digest := sha256.Sum256(payload)
	key, err := storage.NewObjectKey(uuid.NewString(), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	object := GenericObject{Key: key, Size: int64(len(payload))}
	source := syntheticDriver{body: payload, info: storage.ObjectInfo{Key: key, Size: object.Size}}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if err := EncryptGenericObject(ctx, source, object, &encrypted, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	destination, err := storage.NewFileSystem(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	newStaging := func() *os.File {
		t.Helper()
		file, err := os.CreateTemp(t.TempDir(), "staging-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		return file
	}
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreGenericObject(ctx, bytes.NewReader(encrypted.Bytes()), int64(encrypted.Len()), object, wrong, newStaging(), destination); err == nil {
		t.Fatal("wrong identity was accepted")
	}
	if reader, _, err := destination.Open(ctx, key); err == nil {
		_ = reader.Close()
		t.Fatal("failed recovery wrote to destination")
	}
	truncated := encrypted.Bytes()[:encrypted.Len()-1]
	if err := RestoreGenericObject(ctx, bytes.NewReader(truncated), int64(encrypted.Len()), object, identity, newStaging(), destination); err == nil {
		t.Fatal("truncated ciphertext was accepted")
	}
	if reader, _, err := destination.Open(ctx, key); err == nil {
		_ = reader.Close()
		t.Fatal("truncated recovery wrote to destination")
	}
	corruptDestination, err := storage.NewFileSystem(filepath.Join(t.TempDir(), "corrupt-objects"))
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreGenericObject(ctx, bytes.NewReader(encrypted.Bytes()), int64(encrypted.Len()), object, identity, newStaging(), corruptCaptureReadback{Driver: corruptDestination}); err == nil {
		t.Fatal("recovery accepted corrupt destination readback")
	}
	if err := RestoreGenericObject(ctx, bytes.NewReader(encrypted.Bytes()), int64(encrypted.Len()), object, identity, newStaging(), destination); err != nil {
		t.Fatal("restore authenticated object:", err)
	}
	reader, _, err := destination.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	restored, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(restored, payload) {
		t.Fatalf("restored object read=%v close=%v", readErr, closeErr)
	}
	nonempty := newStaging()
	if _, err := nonempty.WriteString("do not overwrite"); err != nil {
		t.Fatal(err)
	}
	if err := RestoreGenericObject(ctx, bytes.NewReader(encrypted.Bytes()), int64(encrypted.Len()), object, identity, nonempty, destination); err == nil {
		t.Fatal("nonempty staging was accepted")
	}
}
