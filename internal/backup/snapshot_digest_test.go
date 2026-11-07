package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestDigestSnapshotRequiresStableBoundedInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data := []byte("synthetic snapshot bytes")
	want := sha256.Sum256(data)
	digest, size, err := DigestSnapshot(ctx, bytes.NewReader(data), int64(len(data)))
	if err != nil || digest != hex.EncodeToString(want[:]) || size != int64(len(data)) {
		t.Fatalf("snapshot digest size=%d error=%v", size, err)
	}
	if digest, size, err := DigestSnapshot(ctx, bytes.NewReader(data), int64(len(data)-1)); err == nil || digest != "" || size != 0 {
		t.Fatal("oversized snapshot returned a digest")
	}
	if _, _, err := DigestSnapshot(ctx, bytes.NewReader(nil), 10); err == nil {
		t.Fatal("empty snapshot was accepted")
	}
	if _, _, err := DigestSnapshot(context.Background(), bytes.NewReader(data), 100); err == nil {
		t.Fatal("snapshot hashing without deadline was accepted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, _, err := DigestSnapshot(canceled, bytes.NewReader(data), 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled snapshot hashing = %v", err)
	}
}
