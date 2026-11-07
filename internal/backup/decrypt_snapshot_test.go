package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestDecryptSnapshotRequiresTrustedCompleteBoundedInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	wrongIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("synthetic stable snapshot")
	var encrypted bytes.Buffer
	metadata, err := EncryptSnapshot(ctx, bytes.NewReader(plain), &encrypted, 4096, 4096, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	var recovered bytes.Buffer
	size, err := DecryptSnapshot(ctx, bytes.NewReader(encrypted.Bytes()), &recovered, int64(encrypted.Len()), int64(len(plain)), metadata.PlainSHA256, identity)
	if err != nil || size != int64(len(plain)) || !bytes.Equal(recovered.Bytes(), plain) {
		t.Fatalf("decrypt snapshot size=%d err=%v", size, err)
	}
	wrongHash := sha256.Sum256([]byte("wrong synthetic snapshot"))
	for _, test := range []struct {
		name      string
		data      []byte
		cipherMax int64
		plainMax  int64
		digest    string
		identity  age.Identity
	}{
		{"wrong key", encrypted.Bytes(), 4096, 4096, metadata.PlainSHA256, wrongIdentity},
		{"truncated", encrypted.Bytes()[:encrypted.Len()-1], 4096, 4096, metadata.PlainSHA256, identity},
		{"cipher limit", encrypted.Bytes(), int64(encrypted.Len() - 1), 4096, metadata.PlainSHA256, identity},
		{"plain limit", encrypted.Bytes(), 4096, int64(len(plain) - 1), metadata.PlainSHA256, identity},
		{"wrong digest", encrypted.Bytes(), 4096, 4096, hex.EncodeToString(wrongHash[:]), identity},
		{"noncanonical digest", encrypted.Bytes(), 4096, 4096, strings.ToUpper(metadata.PlainSHA256), identity},
	} {
		t.Run(test.name, func(t *testing.T) {
			if size, err := DecryptSnapshot(ctx, bytes.NewReader(test.data), io.Discard, test.cipherMax, test.plainMax, test.digest, test.identity); err == nil || size != 0 {
				t.Fatalf("invalid snapshot accepted: size=%d err=%v", size, err)
			}
		})
	}
	if _, err := DecryptSnapshot(context.Background(), bytes.NewReader(encrypted.Bytes()), io.Discard, 4096, 4096, metadata.PlainSHA256, identity); err == nil {
		t.Fatal("decryption without a deadline was accepted")
	}
}
