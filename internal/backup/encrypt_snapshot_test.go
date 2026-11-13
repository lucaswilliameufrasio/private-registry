package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"filippo.io/age"
)

type failedSnapshotWriter struct{}

func (failedSnapshotWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic write failure")
}

func TestEncryptSnapshotBoundedAndAuthenticated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("synthetic stable snapshot")
	var ciphertext bytes.Buffer
	result, err := EncryptSnapshot(ctx, bytes.NewReader(plain), &ciphertext, int64(len(plain)), 4096, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	plainHash := sha256.Sum256(plain)
	cipherHash := sha256.Sum256(ciphertext.Bytes())
	if result.PlainSHA256 != hex.EncodeToString(plainHash[:]) || result.PlainBytes != int64(len(plain)) || result.CipherSHA256 != hex.EncodeToString(cipherHash[:]) || result.CipherBytes != int64(ciphertext.Len()) {
		t.Fatalf("snapshot encryption metadata is incorrect: %+v", result)
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), identity)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(recovered, plain) {
		t.Fatalf("snapshot decrypt error=%v", err)
	}
	for _, limits := range []struct{ plain, cipher int64 }{{int64(len(plain) - 1), 4096}, {4096, 1}} {
		var partial bytes.Buffer
		result, err := EncryptSnapshot(ctx, bytes.NewReader(plain), &partial, limits.plain, limits.cipher, identity.Recipient())
		if err == nil || result != (EncryptedSnapshot{}) {
			t.Fatal("snapshot encryption exceeded a limit without failing")
		}
	}
	if _, err := EncryptSnapshot(context.Background(), bytes.NewReader(plain), io.Discard, 4096, 4096, identity.Recipient()); err == nil {
		t.Fatal("snapshot encryption accepted a context without a deadline")
	}
	if _, err := EncryptSnapshot(ctx, bytes.NewReader(nil), io.Discard, 4096, 4096, identity.Recipient()); err == nil {
		t.Fatal("snapshot encryption accepted an empty snapshot")
	}
	if result, err := EncryptSnapshot(ctx, bytes.NewReader(plain), failedSnapshotWriter{}, 4096, 4096, identity.Recipient()); err == nil || result != (EncryptedSnapshot{}) {
		t.Fatal("failed snapshot writer returned successful metadata")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := EncryptSnapshot(canceled, bytes.NewReader(plain), io.Discard, 4096, 4096, identity.Recipient()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled snapshot encryption = %v", err)
	}
}
