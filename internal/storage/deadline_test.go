package storage

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type deadlineProbe struct {
	opened context.Context
}

func (p *deadlineProbe) Put(ctx context.Context, _ string, _ io.Reader, _ int64) (ObjectInfo, error) {
	if _, ok := ctx.Deadline(); !ok {
		return ObjectInfo{}, errors.New("deadline missing")
	}
	<-ctx.Done()
	return ObjectInfo{}, ctx.Err()
}

func (p *deadlineProbe) Open(ctx context.Context, _ ObjectKey) (io.ReadCloser, ObjectInfo, error) {
	p.opened = ctx
	return io.NopCloser(strings.NewReader("fixture")), ObjectInfo{}, nil
}

func (p *deadlineProbe) OpenRange(ctx context.Context, key ObjectKey, _, _ int64) (io.ReadCloser, ObjectInfo, error) {
	return p.Open(ctx, key)
}

func (p *deadlineProbe) Delete(ctx context.Context, _ ObjectKey) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("deadline missing")
	}
	return ctx.Err()
}

func TestDeadlineStorageBoundsOperationsAndReaderLifetime(t *testing.T) {
	probe := &deadlineProbe{}
	driver, err := NewDeadlineDriver(probe, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Put(context.Background(), "fixture", strings.NewReader("x"), 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("missing operation timeout: %v", err)
	}
	early, cancelEarly := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancelEarly()
	if _, err := driver.Put(early, "fixture", strings.NewReader("x"), 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("earlier parent deadline was lost: %v", err)
	}
	reader, _, err := driver.Open(context.Background(), ObjectKey{})
	if err != nil {
		t.Fatal(err)
	}
	if probe.opened.Err() != nil {
		t.Fatal("reader context cancelled before close")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(probe.opened.Err(), context.Canceled) {
		t.Fatal("reader context remained live after close")
	}
	ranged, _, err := driver.OpenRange(context.Background(), ObjectKey{}, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-probe.opened.Done():
		if !errors.Is(probe.opened.Err(), context.DeadlineExceeded) {
			t.Fatalf("reader context ended unexpectedly: %v", probe.opened.Err())
		}
	case <-time.After(time.Second):
		_ = ranged.Close()
		t.Fatal("reader deadline did not expire")
	}
	if err := ranged.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := driver.Delete(cancelled, ObjectKey{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation was lost: %v", err)
	}
}
