package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"filippo.io/age"
	"private-registry/internal/storage"
)

// DecryptGenericObject verifies the complete age stream, plaintext size and
// digest against independently trusted inventory metadata. Destination bytes
// remain untrusted until nil is returned and must be discarded on any error.
// The caller must authenticate inventory metadata independently before use.
func DecryptGenericObject(ctx context.Context, ciphertext io.Reader, maxCiphertext int64, object GenericObject, destination io.Writer, identity age.Identity) error {
	if ctx == nil || ciphertext == nil || destination == nil || identity == nil || maxCiphertext < 1 || maxCiphertext > 2<<30 || object.Size < 0 || object.Size > 1<<30 {
		return errors.New("generic backup decryption parameters are invalid")
	}
	key, err := storage.NewObjectKey(object.Key.WorkspaceID, object.Key.SHA256)
	if err != nil || key != object.Key {
		return errors.New("generic backup object key is invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	bounded := &io.LimitedReader{R: ciphertext, N: maxCiphertext + 1}
	plaintext, err := age.Decrypt(bounded, identity)
	if err != nil {
		return errors.New("generic backup ciphertext could not be decrypted")
	}
	hash := sha256.New()
	remaining := object.Size
	reader := &io.LimitedReader{R: plaintext, N: object.Size + 1}
	buffer := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := reader.Read(buffer)
		if n > 0 {
			if int64(n) > remaining {
				return errors.New("generic backup plaintext exceeds expected size")
			}
			remaining -= int64(n)
			_, _ = hash.Write(buffer[:n])
			written, writeErr := destination.Write(buffer[:n])
			if writeErr != nil || written != n {
				return errors.New("generic backup plaintext could not be staged")
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return errors.New("generic backup ciphertext failed authentication")
		}
		if n == 0 {
			return errors.New("generic backup ciphertext made no progress")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if bounded.N <= 0 || remaining != 0 || hex.EncodeToString(hash.Sum(nil)) != key.SHA256 {
		return errors.New("generic backup plaintext failed bounds or integrity verification")
	}
	return nil
}
