//go:build !linux

package objectmaint

import "errors"

type InstanceLock struct{}

var ErrInstanceRunning = errors.New("another registry process holds this data directory")

func AcquireInstanceLock(string) (*InstanceLock, error) {
	return nil, errors.New("the registry server is supported on Linux only")
}

func (l *InstanceLock) Release() error { return nil }
