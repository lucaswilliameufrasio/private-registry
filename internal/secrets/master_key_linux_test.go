//go:build linux

package secrets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestMasterKeyFileAndAuthenticatedEncryption(t *testing.T) {
	_, dataDir, keyDir := masterKeyTestDirectories(t)
	keyPath := filepath.Join(keyDir, "master.key")
	if err := InitializeMasterKey(keyPath, dataDir); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected master key permissions: %04o", info.Mode().Perm())
	}
	contents, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) != masterKeySize {
		t.Fatalf("unexpected master key size: %d", len(contents))
	}
	clear(contents)

	key, err := LoadMasterKeyFile(keyPath, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)

	plaintext := []byte("synthetic-totp-seed-material")
	context := []byte("mfa-credential/user-123/totp-seed/v1")
	envelope, err := key.Seal(plaintext, context)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope, plaintext) {
		t.Fatal("encrypted envelope contains the plaintext seed")
	}
	decrypted, err := key.Open(envelope, context)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted value does not match the original plaintext")
	}
	clear(decrypted)

	if _, err := key.Open(envelope, []byte("mfa-credential/other-user/totp-seed/v1")); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("expected context mismatch to fail, got %v", err)
	}
	tampered := bytes.Clone(envelope)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := key.Open(tampered, context); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("expected tampered envelope to fail, got %v", err)
	}
	unknownVersion := bytes.Clone(envelope)
	unknownVersion[0]++
	if _, err := key.Open(unknownVersion, context); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("expected unknown envelope version to fail, got %v", err)
	}
	if _, err := key.Seal(plaintext, nil); !errors.Is(err, ErrEncryptionContext) {
		t.Fatalf("expected empty encryption context to fail, got %v", err)
	}
	if _, err := key.Open(envelope, nil); !errors.Is(err, ErrEncryptionContext) {
		t.Fatalf("expected empty decryption context to fail, got %v", err)
	}
}

func TestMasterKeyRejectsZeroValueAndUseAfterDestroy(t *testing.T) {
	plaintext := []byte("synthetic-secret")
	context := []byte("synthetic-context")
	var zeroValue MasterKey
	if _, err := zeroValue.Seal(plaintext, context); !errors.Is(err, ErrMasterKeyUnavailable) {
		t.Fatalf("expected zero-value key to be rejected, got %v", err)
	}

	_, dataDir, keyDir := masterKeyTestDirectories(t)
	keyPath := filepath.Join(keyDir, "master.key")
	if err := InitializeMasterKey(keyPath, dataDir); err != nil {
		t.Fatal(err)
	}
	key, err := LoadMasterKeyFile(keyPath, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
	if _, err := key.Seal(plaintext, context); !errors.Is(err, ErrMasterKeyUnavailable) {
		t.Fatalf("expected destroyed key to be rejected, got %v", err)
	}
}

func TestInitializeMasterKeyRefusesUnsafeOrExistingPaths(t *testing.T) {
	root, dataDir, keyDir := masterKeyTestDirectories(t)
	insideDataDir := filepath.Join(dataDir, "master.key")
	if err := InitializeMasterKey(insideDataDir, dataDir); !errors.Is(err, ErrUnsafeMasterKeyPath) {
		t.Fatalf("expected a key inside the data directory to be rejected, got %v", err)
	}

	sharedDirectory := filepath.Join(root, "shared")
	if err := os.Mkdir(sharedDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sharedDirectory, 0o777); err != nil {
		t.Fatal(err)
	}
	unsafePath := filepath.Join(sharedDirectory, "master.key")
	if err := InitializeMasterKey(unsafePath, dataDir); !errors.Is(err, ErrUnsafeMasterKeyPath) {
		t.Fatalf("expected a group/world-writable parent to be rejected, got %v", err)
	}

	dataSubdirectory := filepath.Join(dataDir, "nested")
	if err := os.Mkdir(dataSubdirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	dataAlias := filepath.Join(root, "data-alias")
	if err := os.Symlink(dataDir, dataAlias); err != nil {
		t.Fatal(err)
	}
	aliasedDataPath := filepath.Join(dataAlias, "nested", "master.key")
	if err := InitializeMasterKey(aliasedDataPath, dataDir); !errors.Is(err, ErrUnsafeMasterKeyPath) {
		t.Fatalf("expected a symlinked path inside the data directory to be rejected, got %v", err)
	}

	keyPath := filepath.Join(keyDir, "existing.key")
	existing := []byte("do-not-replace")
	if err := os.WriteFile(keyPath, existing, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InitializeMasterKey(keyPath, dataDir); !errors.Is(err, ErrMasterKeyAlreadyExists) {
		t.Fatalf("expected existing key file to be preserved, got %v", err)
	}
	contents, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, existing) {
		t.Fatal("existing file contents changed during initialization")
	}
}

func TestLoadMasterKeyFileRejectsUnsafeFileTypesAndPermissions(t *testing.T) {
	_, dataDir, keyDir := masterKeyTestDirectories(t)
	keyPath := filepath.Join(keyDir, "master.key")
	if err := InitializeMasterKey(keyPath, dataDir); err != nil {
		t.Fatal(err)
	}

	sharedPath := filepath.Join(keyDir, "shared.key")
	if err := os.Link(keyPath, sharedPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKeyFile(keyPath, dataDir); !errors.Is(err, ErrInvalidMasterKeyFile) {
		t.Fatalf("expected hard-linked key file to be rejected, got %v", err)
	}
	if err := os.Remove(sharedPath); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKeyFile(keyPath, dataDir); !errors.Is(err, ErrInvalidMasterKeyFile) {
		t.Fatalf("expected group-readable key file to be rejected, got %v", err)
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKeyFile(keyPath, dataDir); !errors.Is(err, ErrInvalidMasterKeyFile) {
		t.Fatalf("expected invalid key size to be rejected, got %v", err)
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(keyDir, "missing.key"), keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKeyFile(keyPath, dataDir); !errors.Is(err, ErrInvalidMasterKeyFile) {
		t.Fatalf("expected symlink key file to be rejected, got %v", err)
	}
}

func TestConcurrentMasterKeyInitializationHasOneWinner(t *testing.T) {
	_, dataDir, keyDir := masterKeyTestDirectories(t)
	keyPath := filepath.Join(keyDir, "master.key")
	results := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			results <- InitializeMasterKey(keyPath, dataDir)
		}()
	}
	waitGroup.Wait()
	close(results)

	successes := 0
	conflicts := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if errors.Is(err, ErrMasterKeyAlreadyExists) {
			conflicts++
			continue
		}
		t.Fatalf("unexpected initialization error: %v", err)
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("expected one success and one conflict, got %d and %d", successes, conflicts)
	}
	key, err := LoadMasterKeyFile(keyPath, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
}

func masterKeyTestDirectories(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	keyDir := filepath.Join(root, "keys")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return root, dataDir, keyDir
}
