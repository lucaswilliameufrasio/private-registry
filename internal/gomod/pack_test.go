package gomod

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPackDirectory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	mod := []byte("module example.com/private/package\n\ngo 1.24\n")
	if err := os.WriteFile(filepath.Join(source, "go.mod"), mod, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "package.go"), []byte("package example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(root, "module-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = output.Close() })
	packed, err := PackDirectory(ctx, source, "v1.0.0", output, 10)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if packed.ModulePath != "example.com/private/package" || packed.Version != "v1.0.0" || string(packed.ModBytes) != string(mod) || packed.ZipSize != int64(len(data)) || packed.ZipSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("incorrect packed module metadata: %+v", packed)
	}
	if err := ValidatePublication(ctx, packed.ModulePath, packed.Version, packed.ModBytes, output.Name(), 10); err != nil {
		t.Fatalf("packed archive did not pass server validation: %v", err)
	}
	if _, err := PackDirectory(ctx, source, "v1.0.0", output, 10); err == nil {
		t.Fatal("nonempty archive output accepted")
	}
	inside, err := os.CreateTemp(source, "inside-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inside.Close() })
	if _, err := PackDirectory(ctx, source, "v1.0.0", inside, 10); err == nil {
		t.Fatal("archive output inside source directory accepted")
	}
	invalid, err := os.CreateTemp(root, "invalid-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = invalid.Close() })
	if _, err := PackDirectory(ctx, source, "v2.0.0", invalid, 10); err == nil {
		t.Fatal("incompatible module major version accepted")
	}
	if _, err := PackDirectory(context.Background(), source, "v1.0.0", invalid, 10); err == nil {
		t.Fatal("packing without a deadline accepted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := PackDirectory(canceled, source, "v1.0.0", invalid, 10); err == nil {
		t.Fatal("packing with a canceled context accepted")
	}
}
