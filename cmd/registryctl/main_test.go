package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPackGoCommand(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "go.mod"), []byte("module example.com/synthetic/package\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "package.go"), []byte("package synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "module.zip")
	args := []string{"pack", "go", "-dir", source, "-version", "v1.0.0", "-out", output}
	var result bytes.Buffer
	if err := run(context.Background(), args, &result); err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		ModulePath string `json:"module_path"`
		ZipSize    int64  `json:"zip_size"`
	}
	if err := json.Unmarshal(result.Bytes(), &metadata); err != nil || metadata.ModulePath != "example.com/synthetic/package" || metadata.ZipSize <= 0 {
		t.Fatalf("unexpected archive metadata: %+v err=%v", metadata, err)
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), args, &result); err == nil {
		t.Fatal("existing output was overwritten")
	}
	after, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing output changed")
	}
	invalid := filepath.Join(root, "invalid.zip")
	if err := run(context.Background(), []string{"pack", "go", "-dir", source, "-version", "v2.0.0", "-out", invalid}, &result); err == nil {
		t.Fatal("invalid version was accepted")
	}
	if _, err := os.Stat(invalid); !os.IsNotExist(err) {
		t.Fatalf("failed archive was not removed: %v", err)
	}
}
