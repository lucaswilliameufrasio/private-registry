package cargo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"
)

func frame(metadata, archive []byte) []byte {
	var body bytes.Buffer
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(metadata)))
	body.Write(header[:])
	body.Write(metadata)
	binary.LittleEndian.PutUint32(header[:], uint32(len(archive)))
	body.Write(header[:])
	body.Write(archive)
	return body.Bytes()
}

func TestReadPublishFrame(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	metadata, archive := []byte(`{"name":"synthetic"}`), []byte("synthetic crate bytes")
	var output bytes.Buffer
	result, err := ReadPublishFrame(ctx, bytes.NewReader(frame(metadata, archive)), &output, 1024, 1024)
	digest := sha256.Sum256(archive)
	if err != nil || !bytes.Equal(result.Metadata, metadata) || !bytes.Equal(output.Bytes(), archive) || result.Size != int64(len(archive)) || result.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("unexpected framing result: %+v err=%v", result, err)
	}
}

func TestReadPublishFrameRejectsInvalidInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	valid := frame([]byte(`{}`), []byte("crate"))
	for _, tc := range []struct {
		name          string
		data          []byte
		metadataLimit int64
		archiveLimit  int64
	}{
		{"empty", nil, 16, 16},
		{"short metadata length", valid[:3], 16, 16},
		{"short metadata", valid[:5], 16, 16},
		{"short archive length", valid[:8], 16, 16},
		{"short archive", valid[:len(valid)-1], 16, 16},
		{"trailing byte", append(bytes.Clone(valid), 0), 16, 16},
		{"metadata limit", valid, 1, 16},
		{"archive limit", valid, 16, 4},
		{"empty metadata", frame(nil, []byte("crate")), 16, 16},
		{"empty archive", frame([]byte(`{}`), nil), 16, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var destination bytes.Buffer
			if _, err := ReadPublishFrame(ctx, bytes.NewReader(tc.data), &destination, tc.metadataLimit, tc.archiveLimit); err == nil {
				t.Fatal("invalid Cargo frame was accepted")
			}
		})
	}
	if _, err := ReadPublishFrame(context.Background(), bytes.NewReader(valid), io.Discard, 16, 16); err == nil {
		t.Fatal("missing deadline was accepted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := ReadPublishFrame(canceled, bytes.NewReader(valid), io.Discard, 16, 16); err == nil {
		t.Fatal("canceled frame was accepted")
	}
	if _, err := ReadPublishFrame(ctx, bytes.NewReader(valid), failingWriter{}, 16, 16); err == nil {
		t.Fatal("failed staging output was accepted")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic staging failure")
}
