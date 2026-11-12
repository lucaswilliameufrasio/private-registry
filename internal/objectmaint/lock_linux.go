//go:build linux

package objectmaint

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// InstanceLock is held by serve for its whole life and by offline object
// maintenance. It only excludes processes on the same host that use the same
// data directory: with PostgreSQL and several hosts, the operator must stop
// every serve before running offline maintenance.
type InstanceLock struct {
	file *os.File
}

var ErrInstanceRunning = errors.New("another registry process holds this data directory; stop serve before offline maintenance")

func AcquireInstanceLock(dataDir string) (*InstanceLock, error) {
	if !filepath.IsAbs(dataDir) {
		return nil, errors.New("data directory must be absolute")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, errors.New("data directory could not be created")
	}
	info, err := os.Lstat(dataDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("data directory must be private to its owner")
	}
	path := filepath.Join(dataDir, "registry.instance.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("instance lock could not be opened")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrInstanceRunning
		}
		return nil, errors.New("instance lock could not be acquired")
	}
	return &InstanceLock{file: file}, nil
}

func (l *InstanceLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
