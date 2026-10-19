//go:build !linux

package secrets

import (
	"errors"
	"testing"
)

func TestMasterKeyFilesAreUnsupportedOutsideLinux(t *testing.T) {
	if err := InitializeMasterKey("/tmp/master.key", "/tmp/data"); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("expected unsupported-platform error, got %v", err)
	}
	if _, err := LoadMasterKeyFile("/tmp/master.key", "/tmp/data"); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("expected unsupported-platform error, got %v", err)
	}
}
