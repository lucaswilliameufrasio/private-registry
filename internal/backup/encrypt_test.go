package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"filippo.io/age"
	"github.com/google/uuid"
	"private-registry/internal/storage"
)

func TestEncryptGenericObjectVerifiesBeforeAcceptingOutput(t *testing.T) {
	payload := []byte("synthetic encrypted object")
	digest := sha256.Sum256(payload)
	key, err := storage.NewObjectKey(uuid.NewString(), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	object := GenericObject{Key: key, Size: int64(len(payload))}
	driver := syntheticDriver{body: payload, info: storage.ObjectInfo{Key: key, Size: object.Size}}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	if err := EncryptGenericObject(context.Background(), driver, object, &ciphertext, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	plaintext, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), identity)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(plaintext)
	if err != nil || !bytes.Equal(decoded, payload) {
		t.Fatalf("decrypt verified object: %v", err)
	}
	driver.body = bytes.Repeat([]byte{'x'}, len(payload))
	ciphertext.Reset()
	if err := EncryptGenericObject(context.Background(), driver, object, &ciphertext, identity.Recipient()); err == nil {
		t.Fatal("corrupt source produced acceptable ciphertext")
	}
	if err := EncryptGenericObject(context.Background(), driver, object, io.Discard, nil); err == nil {
		t.Fatal("missing recipient was accepted")
	}
}
