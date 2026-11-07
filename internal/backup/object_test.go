package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"
	"private-registry/internal/storage"
)

type syntheticDriver struct {
	storage.Driver
	body     []byte
	info     storage.ObjectInfo
	closeErr error
}

func TestCiphertextReadbackAllowsEncryptionOverhead(t *testing.T) {
	digest := sha256.Sum256([]byte("synthetic"))
	key, err := storage.NewObjectKey(uuid.NewString(), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	object := GenericObject{Key: key, Size: (1 << 30) + 1}
	driver := syntheticDriver{info: storage.ObjectInfo{Key: key, Size: object.Size}}
	if err := CopyGenericObject(context.Background(), driver, object, io.Discard); err == nil || !strings.Contains(err.Error(), "parameters") {
		t.Fatalf("plaintext limit not enforced: %v", err)
	}
	if err := copyBoundedObject(context.Background(), driver, object, io.Discard, 2<<30); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("ciphertext readback must reach and reject truncated content: %v", err)
	}
}

func (s syntheticDriver) Open(_ context.Context, _ storage.ObjectKey) (io.ReadCloser, storage.ObjectInfo, error) {
	return syntheticReader{Reader: bytes.NewReader(s.body), closeErr: s.closeErr}, s.info, nil
}

type syntheticReader struct {
	*bytes.Reader
	closeErr error
}

func (s syntheticReader) Close() error {
	return s.closeErr
}

func TestCopyGenericObjectRejectsIncompleteOrCorruptCopies(t *testing.T) {
	payload := []byte("synthetic backup object")
	digest := sha256.Sum256(payload)
	key, err := storage.NewObjectKey(uuid.NewString(), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	object := GenericObject{Key: key, Size: int64(len(payload))}
	driver := syntheticDriver{body: payload, info: storage.ObjectInfo{Key: key, Size: object.Size}}
	var result bytes.Buffer
	if err := CopyGenericObject(context.Background(), driver, object, &result); err != nil || !bytes.Equal(result.Bytes(), payload) {
		t.Fatalf("copy verified object: %v", err)
	}
	for _, tc := range []struct {
		name     string
		body     []byte
		closeErr error
	}{
		{name: "truncated", body: payload[:len(payload)-1]},
		{name: "oversized", body: append(bytes.Clone(payload), 'x')},
		{name: "corrupt", body: bytes.Repeat([]byte{'x'}, len(payload))},
		{name: "close failure", body: payload, closeErr: errors.New("synthetic")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			driver.body = tc.body
			driver.closeErr = tc.closeErr
			if err := CopyGenericObject(context.Background(), driver, object, io.Discard); err == nil {
				t.Fatal("invalid source was accepted")
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CopyGenericObject(canceled, driver, object, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled copy error = %v", err)
	}
}
