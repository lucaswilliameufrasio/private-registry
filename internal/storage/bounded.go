package storage

import (
	"context"
	"errors"
	"io"
	"sync"
)

// ErrCapacity indicates that all configured storage operation slots are held.
var ErrCapacity = errors.New("object storage capacity is temporarily unavailable")

// BoundedDriver limits concurrent operations of one driver instance. Readers
// retain their slots until closed; callers must always close them. It does not
// coordinate instances, enforce filesystem quotas, or account for files left by
// failed cleanup or a crash. A Put may need two staging files concurrently.
type BoundedDriver struct {
	driver Driver
	slots  chan struct{}
}

func NewBoundedDriver(driver Driver, maxConcurrent int) (*BoundedDriver, error) {
	if driver == nil || maxConcurrent < 1 || maxConcurrent > 128 {
		return nil, errors.New("bounded storage configuration is invalid")
	}
	return &BoundedDriver{driver: driver, slots: make(chan struct{}, maxConcurrent)}, nil
}

func (s *BoundedDriver) acquire(ctx context.Context) error {
	if s == nil || s.driver == nil || ctx == nil {
		return errors.New("bounded storage is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.slots <- struct{}{}:
		return nil
	default:
		return ErrCapacity
	}
}

func (s *BoundedDriver) release() {
	<-s.slots
}

func (s *BoundedDriver) Put(ctx context.Context, workspaceID string, source io.Reader, maxBytes int64) (ObjectInfo, error) {
	if err := s.acquire(ctx); err != nil {
		return ObjectInfo{}, err
	}
	defer s.release()
	return s.driver.Put(ctx, workspaceID, source, maxBytes)
}

func (s *BoundedDriver) Open(ctx context.Context, key ObjectKey) (io.ReadCloser, ObjectInfo, error) {
	if err := s.acquire(ctx); err != nil {
		return nil, ObjectInfo{}, err
	}
	reader, info, err := s.driver.Open(ctx, key)
	if err != nil {
		if reader != nil {
			err = errors.Join(err, reader.Close())
		}
		s.release()
		return nil, ObjectInfo{}, err
	}
	if reader == nil {
		s.release()
		return nil, ObjectInfo{}, errors.New("object storage returned an empty reader")
	}
	return &boundedReader{ReadCloser: reader, release: s.release}, info, nil
}

func (s *BoundedDriver) OpenRange(ctx context.Context, key ObjectKey, offset, length int64) (io.ReadCloser, ObjectInfo, error) {
	if err := s.acquire(ctx); err != nil {
		return nil, ObjectInfo{}, err
	}
	reader, info, err := s.driver.OpenRange(ctx, key, offset, length)
	if err != nil {
		if reader != nil {
			err = errors.Join(err, reader.Close())
		}
		s.release()
		return nil, ObjectInfo{}, err
	}
	if reader == nil {
		s.release()
		return nil, ObjectInfo{}, errors.New("object storage returned an empty reader")
	}
	return &boundedReader{ReadCloser: reader, release: s.release}, info, nil
}

func (s *BoundedDriver) Delete(ctx context.Context, key ObjectKey) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	return s.driver.Delete(ctx, key)
}

type boundedReader struct {
	io.ReadCloser
	release func()
	once    sync.Once
	err     error
}

func (r *boundedReader) Close() error {
	r.once.Do(func() {
		r.err = r.ReadCloser.Close()
		r.release()
	})
	return r.err
}
