package secrets

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	masterKeySize      = chacha20poly1305.KeySize
	envelopeVersionV1  = byte(1)
	envelopeHeaderSize = 1 + chacha20poly1305.NonceSizeX
)

var (
	ErrMasterKeyPathRequired  = errors.New("master key file path and data directory are required")
	ErrUnsafeMasterKeyPath    = errors.New("master key file must be private and outside the data directory")
	ErrMasterKeyAlreadyExists = errors.New("master key file already exists; refusing to overwrite it")
	ErrInvalidMasterKeyFile   = errors.New("master key file is invalid or unsafe")
	ErrMasterKeyUnavailable   = errors.New("master key is unavailable")
	ErrUnsupportedPlatform    = errors.New("local master key files are supported only on Linux servers")
	ErrEncryptionContext      = errors.New("secret encryption context is required")
	ErrInvalidEnvelope        = errors.New("encrypted secret is invalid")
)

type MasterKey struct {
	key   [masterKeySize]byte
	valid bool
}

// InitializeMasterKey generates a new local key file without replacing an existing file.
func InitializeMasterKey(path, dataDir string) error {
	if !masterKeyFilesSupported() {
		return ErrUnsupportedPlatform
	}
	if err := validateMasterKeyPaths(path, dataDir); err != nil {
		return err
	}

	var key [masterKeySize]byte
	defer clear(key[:])
	if _, err := rand.Read(key[:]); err != nil {
		return errors.New("master key could not be generated")
	}

	return createMasterKeyFile(filepath.Clean(path), key[:])
}

// LoadMasterKeyFile loads a private Linux key file after validating its path and metadata.
func LoadMasterKeyFile(path, dataDir string) (MasterKey, error) {
	if !masterKeyFilesSupported() {
		return MasterKey{}, ErrUnsupportedPlatform
	}
	if err := validateMasterKeyPaths(path, dataDir); err != nil {
		return MasterKey{}, err
	}

	encodedKey, err := readMasterKeyFile(filepath.Clean(path))
	if err != nil {
		return MasterKey{}, err
	}
	defer clear(encodedKey)
	if len(encodedKey) != masterKeySize {
		return MasterKey{}, ErrInvalidMasterKeyFile
	}

	var key MasterKey
	copy(key.key[:], encodedKey)
	key.valid = true
	return key, nil
}

// Seal returns a versioned authenticated envelope using context as additional data.
func (key *MasterKey) Seal(plaintext, context []byte) ([]byte, error) {
	if key == nil || !key.valid {
		return nil, ErrMasterKeyUnavailable
	}
	if len(context) == 0 {
		return nil, ErrEncryptionContext
	}
	aead, err := chacha20poly1305.NewX(key.key[:])
	if err != nil {
		return nil, ErrInvalidMasterKeyFile
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	defer clear(nonce)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("secret nonce could not be generated")
	}
	envelope := make([]byte, envelopeHeaderSize, envelopeHeaderSize+len(plaintext)+aead.Overhead())
	envelope[0] = envelopeVersionV1
	copy(envelope[1:], nonce)
	envelope = aead.Seal(envelope, nonce, plaintext, context)
	return envelope, nil
}

// Open authenticates and decrypts an envelope using its original additional data.
func (key *MasterKey) Open(envelope, context []byte) ([]byte, error) {
	if key == nil || !key.valid {
		return nil, ErrMasterKeyUnavailable
	}
	if len(context) == 0 {
		return nil, ErrEncryptionContext
	}
	if len(envelope) < envelopeHeaderSize+chacha20poly1305.Overhead || envelope[0] != envelopeVersionV1 {
		return nil, ErrInvalidEnvelope
	}
	aead, err := chacha20poly1305.NewX(key.key[:])
	if err != nil {
		return nil, ErrInvalidMasterKeyFile
	}
	nonce := envelope[1:envelopeHeaderSize]
	plaintext, err := aead.Open(nil, nonce, envelope[envelopeHeaderSize:], context)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	return plaintext, nil
}

// Destroy clears the key held by this value and prevents later use of it.
func (key *MasterKey) Destroy() {
	if key == nil {
		return
	}
	clear(key.key[:])
	key.valid = false
}

func validateMasterKeyPaths(path, dataDir string) error {
	if path == "" || dataDir == "" || !filepath.IsAbs(path) || !filepath.IsAbs(dataDir) {
		return ErrMasterKeyPathRequired
	}
	path = filepath.Clean(path)
	dataDir = filepath.Clean(dataDir)

	resolvedDataDir, err := canonicalizePath(dataDir)
	if err != nil {
		return ErrUnsafeMasterKeyPath
	}
	if dataInfo, err := os.Stat(dataDir); err == nil {
		if !dataInfo.IsDir() {
			return ErrUnsafeMasterKeyPath
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return ErrUnsafeMasterKeyPath
	}

	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() {
		return ErrUnsafeMasterKeyPath
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil || !isSecureMasterKeyDirectory(resolvedParent) {
		return ErrUnsafeMasterKeyPath
	}
	resolvedKeyPath := filepath.Join(resolvedParent, filepath.Base(path))
	if pathIsWithin(resolvedDataDir, resolvedKeyPath) {
		return ErrUnsafeMasterKeyPath
	}
	return nil
}

func canonicalizePath(path string) (string, error) {
	current := filepath.Clean(path)
	missingComponents := make([]string, 0)
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for index := len(missingComponents) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missingComponents[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if _, statErr := os.Lstat(current); statErr == nil || !errors.Is(statErr, fs.ErrNotExist) {
			return "", err
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		missingComponents = append(missingComponents, filepath.Base(current))
		current = parent
	}
}

func pathIsWithin(directory, path string) bool {
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return true
	}
	return relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
