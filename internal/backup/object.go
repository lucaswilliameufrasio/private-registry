package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"private-registry/internal/storage"
)

// CopyGenericObject copies one inventoried object and verifies its size and
// SHA-256. The destination is untrusted until this function returns nil; callers
// must discard partial output on any error and publish it only after success.
// This operation neither pins the source nor creates a complete backup.
func CopyGenericObject(ctx context.Context, source storage.Driver, object GenericObject, destination io.Writer) (retErr error) {
	if ctx == nil || source == nil || destination == nil || object.Size < 0 || object.Size > 1<<30 {
		return errors.New("generic backup object copy parameters are invalid")
	}
	key, err := storage.NewObjectKey(object.Key.WorkspaceID, object.Key.SHA256)
	if err != nil || key != object.Key {
		return errors.New("generic backup object key is invalid")
	}
	reader, info, err := source.Open(ctx, key)
	if err != nil {
		return errors.New("generic backup source object could not be opened")
	}
	if reader == nil {
		return errors.New("generic backup source object reader is unavailable")
	}
	defer func() {
		if err := reader.Close(); err != nil {
			retErr = errors.Join(retErr, errors.New("generic backup source object could not be closed"))
		}
	}()
	if info.Key != key || info.Size != object.Size {
		return errors.New("generic backup source metadata does not match inventory")
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: reader, N: object.Size + 1}
	buffer := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := limited.Read(buffer)
		if n > 0 {
			if int64(n) > object.Size {
				return errors.New("generic backup source object exceeds expected size")
			}
			object.Size -= int64(n)
			if _, err := hash.Write(buffer[:n]); err != nil {
				return errors.New("generic backup object digest could not be calculated")
			}
			written, err := destination.Write(buffer[:n])
			if err != nil || written != n {
				return errors.New("generic backup object could not be copied")
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return errors.New("generic backup source object could not be read")
		}
		if n == 0 {
			return errors.New("generic backup source object made no progress")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if object.Size != 0 || hex.EncodeToString(hash.Sum(nil)) != key.SHA256 {
		return errors.New("generic backup source object failed integrity verification")
	}
	return nil
}
