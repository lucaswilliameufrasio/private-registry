//go:build !windows

package storage

import (
	"errors"
	"os"
)

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return errors.New("object directory could not be opened")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("object directory could not be synchronized")
	}
	return nil
}
