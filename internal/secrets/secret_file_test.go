//go:build linux

package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSecretFileRequiresPrivateWellFormedFile(t *testing.T) {
	directory := t.TempDir()
	write := func(name, contents string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if got, err := LoadSecretFile(write("ok", "synthetic-credential\n", 0o600)); err != nil || got != "synthetic-credential" {
		t.Fatalf("private secret file = %q, %v", got, err)
	}
	if got, err := LoadSecretFile(write("readonly", "synthetic-credential", 0o400)); err != nil || got != "synthetic-credential" {
		t.Fatalf("read-only secret file = %q, %v", got, err)
	}
	for name, path := range map[string]string{
		"group readable": write("group", "synthetic", 0o640),
		"world readable": write("world", "synthetic", 0o604),
		"empty":          write("empty", "\n", 0o600),
		"inner space":    write("space", "two words", 0o600),
		"two lines":      write("lines", "one\ntwo\n", 0o600),
		"oversized":      write("big", strings.Repeat("a", maxSecretFileBytes+1), 0o600),
		"missing":        filepath.Join(directory, "absent"),
	} {
		if got, err := LoadSecretFile(path); err == nil || got != "" {
			t.Errorf("%s secret file was accepted", name)
		}
	}
	target := write("target", "synthetic", 0o600)
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecretFile(link); err == nil {
		t.Error("symlinked secret file was accepted")
	}
	hard := filepath.Join(directory, "hard")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecretFile(target); err == nil {
		t.Error("multiply linked secret file was accepted")
	}
}
