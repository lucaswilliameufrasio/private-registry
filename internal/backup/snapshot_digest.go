package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// DigestSnapshot hashes a caller-provided stable snapshot with a strict byte
// limit. The caller must create the snapshot using the database's supported
// mechanism; passing a live database file does not produce a valid snapshot.
// The caller also owns the reader, snapshot identity and filesystem isolation.
func DigestSnapshot(ctx context.Context, snapshot io.Reader, maxBytes int64) (string, int64, error) {
	if ctx == nil || snapshot == nil || maxBytes < 1 || maxBytes > 1<<40 {
		return "", 0, errors.New("backup snapshot digest parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return "", 0, errors.New("backup snapshot digest requires a deadline")
	}
	hash := sha256.New()
	reader := &io.LimitedReader{R: snapshot, N: maxBytes + 1}
	buffer := make([]byte, 32*1024)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		n, readErr := reader.Read(buffer)
		if n > 0 {
			size += int64(n)
			if size > maxBytes {
				return "", 0, errors.New("backup snapshot exceeds its byte limit")
			}
			_, _ = hash.Write(buffer[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", 0, errors.New("backup snapshot could not be read")
		}
		if n == 0 {
			return "", 0, errors.New("backup snapshot made no progress")
		}
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	if size == 0 {
		return "", 0, errors.New("backup snapshot is empty")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}
