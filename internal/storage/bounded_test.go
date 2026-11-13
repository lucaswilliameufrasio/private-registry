package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

type observedBoundedReader struct{ reads int }

type errorWithReaderDriver struct {
	Driver
	closed atomic.Int32
}

type observedCloseReader struct {
	io.Reader
	closed *atomic.Int32
}

func (r *observedCloseReader) Close() error {
	r.closed.Add(1)
	return nil
}

func (d *errorWithReaderDriver) Open(context.Context, ObjectKey) (io.ReadCloser, ObjectInfo, error) {
	return &observedCloseReader{Reader: bytes.NewReader(nil), closed: &d.closed}, ObjectInfo{}, errors.New("synthetic read failure")
}

func (d *errorWithReaderDriver) OpenRange(ctx context.Context, key ObjectKey, _, _ int64) (io.ReadCloser, ObjectInfo, error) {
	return d.Open(ctx, key)
}

func (r *observedBoundedReader) Read([]byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

func TestBoundedStorageRetainsReaderSlotAndReleasesOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	objects, err := NewFileSystem(filepath.Join(t.TempDir(), "objects"))
	if err != nil {
		t.Fatal(err)
	}
	bounded, err := NewBoundedDriver(objects, 1)
	if err != nil {
		t.Fatal(err)
	}
	workspace := uuid.NewString()
	info, err := bounded.Put(ctx, workspace, bytes.NewReader([]byte("fixture")), 16)
	if err != nil {
		t.Fatal(err)
	}
	reader, _, err := bounded.OpenRange(ctx, info.Key, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	source := &observedBoundedReader{}
	if _, err := bounded.Put(ctx, workspace, source, 16); !errors.Is(err, ErrCapacity) || source.reads != 0 {
		t.Fatalf("capacity did not reject before reading: reads=%d err=%v", source.reads, err)
	}
	if _, _, err := bounded.Open(ctx, info.Key); !errors.Is(err, ErrCapacity) {
		t.Fatalf("concurrent open bypassed capacity: %v", err)
	}
	var group sync.WaitGroup
	errorsFound := make(chan error, 2)
	for range 2 {
		group.Go(func() { errorsFound <- reader.Close() })
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	reader, _, err = bounded.Open(ctx, info.Key)
	if err != nil {
		t.Fatalf("slot not released: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bounded.Open(ctx, ObjectKey{}); err == nil {
		t.Fatal("invalid key accepted")
	}
	reader, _, err = bounded.Open(ctx, info.Key)
	if err != nil {
		t.Fatalf("failed open leaked slot: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := bounded.Put(ctx, workspace, source, 16); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled operation accepted: %v", err)
	}
}

func TestStorageWrappersCloseReaderReturnedWithError(t *testing.T) {
	probe := &errorWithReaderDriver{}
	bounded, err := NewBoundedDriver(probe, 1)
	if err != nil {
		t.Fatal(err)
	}
	timed, err := NewDeadlineDriver(probe, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, driver := range []Driver{bounded, timed} {
		if reader, _, err := driver.Open(context.Background(), ObjectKey{}); err == nil || reader != nil {
			t.Fatal("open returned a reader despite an error")
		}
		if reader, _, err := driver.OpenRange(context.Background(), ObjectKey{}, 0, 1); err == nil || reader != nil {
			t.Fatal("range returned a reader despite an error")
		}
	}
	if got := probe.closed.Load(); got != 4 {
		t.Fatalf("readers returned with errors were not closed: %d", got)
	}
}
