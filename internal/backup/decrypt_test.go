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

func TestDecryptGenericObjectRejectsUntrustedCiphertext(t *testing.T) {
	payload := []byte("synthetic encrypted recovery object")
	digest := sha256.Sum256(payload)
	key, err := storage.NewObjectKey(uuid.NewString(), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	object := GenericObject{Key: key, Size: int64(len(payload))}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	wrongIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	driver := syntheticDriver{body: payload, info: storage.ObjectInfo{Key: key, Size: object.Size}}
	var sealed bytes.Buffer
	if err := EncryptGenericObject(context.Background(), driver, object, &sealed, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := DecryptGenericObject(context.Background(), bytes.NewReader(sealed.Bytes()), int64(sealed.Len()), object, &output, identity); err != nil || !bytes.Equal(output.Bytes(), payload) {
		t.Fatalf("decrypt valid object: %v", err)
	}
	if err := DecryptGenericObject(context.Background(), bytes.NewReader(sealed.Bytes()), int64(sealed.Len()), object, io.Discard, wrongIdentity); err == nil {
		t.Fatal("wrong identity accepted")
	}
	if err := DecryptGenericObject(context.Background(), bytes.NewReader(sealed.Bytes()[:sealed.Len()-1]), int64(sealed.Len()), object, io.Discard, identity); err == nil {
		t.Fatal("truncated ciphertext accepted")
	}
	if err := DecryptGenericObject(context.Background(), bytes.NewReader(sealed.Bytes()), int64(sealed.Len()-1), object, io.Discard, identity); err == nil {
		t.Fatal("ciphertext beyond limit accepted")
	}
	withTrailing := append(bytes.Clone(sealed.Bytes()), []byte("untrusted trailing bytes")...)
	if err := DecryptGenericObject(context.Background(), bytes.NewReader(withTrailing), int64(len(withTrailing)), object, io.Discard, identity); err == nil {
		t.Fatal("ciphertext with trailing bytes accepted")
	}
	wrongObject := object
	wrongObject.Size--
	if err := DecryptGenericObject(context.Background(), bytes.NewReader(sealed.Bytes()), int64(sealed.Len()), wrongObject, io.Discard, identity); err == nil {
		t.Fatal("plaintext beyond inventory size accepted")
	}
	wrongObject = object
	wrongObject.Key.SHA256 = hex.EncodeToString(make([]byte, sha256.Size))
	if err := DecryptGenericObject(context.Background(), bytes.NewReader(sealed.Bytes()), int64(sealed.Len()), wrongObject, io.Discard, identity); err == nil {
		t.Fatal("incorrect inventory digest accepted")
	}
}
