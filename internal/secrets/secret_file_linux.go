//go:build linux

package secrets

import (
	"io"
	"os"
	"syscall"
)

func readPrivateFile(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidSecretFile
	}
	file := os.NewFile(uintptr(fd), "registry-secret")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrInvalidSecretFile
	}
	defer func() {
		_ = file.Close()
	}()
	info, err := file.Stat()
	if err != nil || !isPrivateRegularKeyFile(info) {
		return nil, ErrInvalidSecretFile
	}
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(contents)) > limit {
		clear(contents)
		return nil, ErrInvalidSecretFile
	}
	return contents, nil
}
