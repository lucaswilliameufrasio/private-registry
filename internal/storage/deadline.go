package storage

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// DeadlineDriver places an explicit upper bound on each storage operation.
// Returned readers keep the derived context until closed or timed out; callers
// must still close readers to release the underlying resources.
type DeadlineDriver struct {
	driver  Driver
	timeout time.Duration
}

func NewDeadlineDriver(driver Driver, timeout time.Duration) (*DeadlineDriver, error) {
	if driver == nil || timeout <= 0 || timeout > time.Hour {
		return nil, errors.New("storage deadline configuration is invalid")
	}
	return &DeadlineDriver{driver: driver, timeout: timeout}, nil
}

func (s *DeadlineDriver) operation(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if s == nil || s.driver == nil || ctx == nil {
		return nil, nil, errors.New("deadline storage is unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, s.timeout)
	return bounded, cancel, nil
}

func (s *DeadlineDriver) Put(ctx context.Context, workspaceID string, source io.Reader, maxBytes int64) (ObjectInfo, error) {
	bounded, cancel, err := s.operation(ctx)
	if err != nil {
		return ObjectInfo{}, err
	}
	defer cancel()
	return s.driver.Put(bounded, workspaceID, source, maxBytes)
}

func (s *DeadlineDriver) Open(ctx context.Context, key ObjectKey) (io.ReadCloser, ObjectInfo, error) {
	bounded, cancel, err := s.operation(ctx)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	reader, info, err := s.driver.Open(bounded, key)
	if err != nil {
		if reader != nil {
			err = errors.Join(err, reader.Close())
		}
		cancel()
		return nil, ObjectInfo{}, err
	}
	if reader == nil {
		cancel()
		return nil, ObjectInfo{}, errors.New("object storage returned an empty reader")
	}
	return &deadlineReader{ReadCloser: reader, cancel: cancel}, info, nil
}

func (s *DeadlineDriver) OpenRange(ctx context.Context, key ObjectKey, offset, length int64) (io.ReadCloser, ObjectInfo, error) {
	bounded, cancel, err := s.operation(ctx)
	if err != nil {
		return nil, ObjectInfo{}, err
	}
	reader, info, err := s.driver.OpenRange(bounded, key, offset, length)
	if err != nil {
		if reader != nil {
			err = errors.Join(err, reader.Close())
		}
		cancel()
		return nil, ObjectInfo{}, err
	}
	if reader == nil {
		cancel()
		return nil, ObjectInfo{}, errors.New("object storage returned an empty reader")
	}
	return &deadlineReader{ReadCloser: reader, cancel: cancel}, info, nil
}

func (s *DeadlineDriver) Delete(ctx context.Context, key ObjectKey) error {
	bounded, cancel, err := s.operation(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	return s.driver.Delete(bounded, key)
}

type deadlineReader struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
	err    error
}

func (r *deadlineReader) Close() error {
	r.once.Do(func() {
		r.err = r.ReadCloser.Close()
		r.cancel()
	})
	return r.err
}
