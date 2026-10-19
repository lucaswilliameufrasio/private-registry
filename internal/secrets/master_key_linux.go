//go:build linux

package secrets

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func createMasterKeyFile(path string, key []byte) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return ErrMasterKeyAlreadyExists
		}
		return errors.New("master key file could not be created")
	}
	file := os.NewFile(uintptr(fd), "registry-master-key")
	if file == nil {
		_ = syscall.Close(fd)
		_ = os.Remove(path)
		return errors.New("master key file could not be created")
	}
	created := false
	defer func() {
		if !created {
			_ = os.Remove(path)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return errors.New("master key file permissions could not be set")
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		return errors.New("master key file could not be written")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("master key file could not be synchronized")
	}
	if err := file.Close(); err != nil {
		return errors.New("master key file could not be closed")
	}
	created = true

	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("master key directory could not be opened")
	}
	defer func() {
		_ = directory.Close()
	}()
	if err := directory.Sync(); err != nil {
		return errors.New("master key directory could not be synchronized")
	}
	return nil
}

func masterKeyFilesSupported() bool {
	return true
}

func readMasterKeyFile(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidMasterKeyFile
	}
	file := os.NewFile(uintptr(fd), "registry-master-key")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrInvalidMasterKeyFile
	}
	defer func() {
		_ = file.Close()
	}()

	info, err := file.Stat()
	if err != nil || !isPrivateRegularKeyFile(info) {
		return nil, ErrInvalidMasterKeyFile
	}
	contents, err := io.ReadAll(io.LimitReader(file, masterKeySize+1))
	if err != nil || len(contents) != masterKeySize {
		clear(contents)
		return nil, ErrInvalidMasterKeyFile
	}
	return contents, nil
}

func isPrivateRegularKeyFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o400 == 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return false
	}
	return true
}

func isSecureMasterKeyDirectory(path string) bool {
	current := filepath.Clean(path)
	for {
		info, err := os.Stat(current)
		if err != nil || !info.IsDir() {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) && stat.Uid != 0 {
			return false
		}
		if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return false
		}
		parent := filepath.Dir(current)
		if parent == current {
			return true
		}
		current = parent
	}
}
