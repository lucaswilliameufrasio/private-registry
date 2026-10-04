package sqlitebackup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func TestEncryptedRoundtripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	want := bytes.Repeat([]byte("synthetic private metadata"), 8192)
	if err := os.WriteFile(source, want, 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	sealed := filepath.Join(dir, "backup.age")
	if err := Encrypt(context.Background(), source, sealed, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("synthetic private metadata")) {
		t.Fatal("plaintext found in backup")
	}
	restored := filepath.Join(dir, "restored.db")
	if err := Decrypt(context.Background(), sealed, restored, identity); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(restored)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("roundtrip differs: %v", err)
	}
	for _, path := range []string{sealed, restored} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe permissions on %s: %v", path, info.Mode())
		}
	}
}

func TestDecryptRejectsWrongKeyTamperAndTruncation(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, bytes.Repeat([]byte("private"), 20000), 0o600); err != nil {
		t.Fatal(err)
	}
	sealed := filepath.Join(dir, "original.age")
	if err := Encrypt(context.Background(), source, sealed, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"wrong key", "tamper", "truncated", "invalid header"} {
		t.Run(kind, func(t *testing.T) {
			data := bytes.Clone(original)
			key := identity
			switch kind {
			case "wrong key":
				key = wrong
			case "tamper":
				data[len(data)-1] ^= 0xff
			case "truncated":
				data = data[:len(data)-32]
			case "invalid header":
				data = []byte("not an age file")
			}
			input := filepath.Join(t.TempDir(), "bad.age")
			if err := os.WriteFile(input, data, 0o600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "must-not-exist.db")
			if err := Decrypt(context.Background(), input, output, key); err == nil {
				t.Fatal("invalid backup accepted")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial plaintext retained: %v", err)
			}
		})
	}
}

func TestTransformFailuresAndCancellation(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := Encrypt(context.Background(), source, filepath.Join(dir, "nil-recipient"), nil); err == nil {
		t.Fatal("nil recipient accepted")
	}
	if err := Decrypt(context.Background(), source, filepath.Join(dir, "nil-identity"), nil); err == nil {
		t.Fatal("nil identity accepted")
	}
	if err := Encrypt(context.Background(), filepath.Join(dir, "missing"), filepath.Join(dir, "missing-output"), identity.Recipient()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing source, got %v", err)
	}
	if err := Encrypt(context.Background(), source, source, identity.Recipient()); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected no-overwrite error, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	output := filepath.Join(dir, "canceled")
	err = transform(ctx, source, output, func(in io.Reader, out io.Writer) error {
		cancel()
		_, err := io.Copy(out, in)
		return err
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled output retained: %v", err)
	}
	if err := Encrypt(ctx, source, output, identity.Recipient()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request accepted: %v", err)
	}
	if _, err := Digest(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing digest source accepted: %v", err)
	}
}
