//go:build linux

package migrations

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireSQLiteFileLockHonorsCancellation(t *testing.T) {
	cfg := sqliteConfig(t)
	if err := os.MkdirAll(filepath.Dir(cfg.DatabaseDSN), 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := acquireSQLiteFileLock(context.Background(), cfg.DatabaseDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unlock(); err != nil {
			t.Errorf("release migration lock: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := acquireSQLiteFileLock(ctx, cfg.DatabaseDSN); err == nil {
		t.Fatal("second migration lock unexpectedly acquired")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock wait did not honor context deadline: %v", err)
	}
}
