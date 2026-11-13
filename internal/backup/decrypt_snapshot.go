package backup

import (
	"context"
	"encoding/hex"
	"errors"
	"io"

	"filippo.io/age"
)

// DecryptSnapshot authenticates an age stream and compares its plaintext with
// an independently trusted SHA-256 digest. Output must be private staging and
// discarded on any error; it is not safe to consume until this returns nil.
// The caller supplies independent trust, a hard storage quota and readers and
// writers that do not block indefinitely. It does not establish backup
// completeness, freshness, schema compatibility or recovery isolation.
func DecryptSnapshot(ctx context.Context, ciphertext io.Reader, destination io.Writer, maxCiphertext, maxPlaintext int64, expectedSHA256 string, identity age.Identity) (int64, error) {
	if ctx == nil || ciphertext == nil || destination == nil || identity == nil || maxCiphertext < 1 || maxCiphertext > 1<<40 || maxPlaintext < 1 || maxPlaintext > 1<<40 {
		return 0, errors.New("snapshot decryption parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return 0, errors.New("snapshot decryption requires a deadline")
	}
	digestBytes, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(digestBytes) != 32 || hex.EncodeToString(digestBytes) != expectedSHA256 {
		return 0, errors.New("trusted snapshot digest is invalid")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	bounded := &io.LimitedReader{R: ciphertext, N: maxCiphertext + 1}
	plaintext, err := age.Decrypt(bounded, identity)
	if err != nil {
		return 0, errors.New("snapshot ciphertext could not be decrypted")
	}
	digest, size, err := DigestSnapshot(ctx, io.TeeReader(plaintext, destination), maxPlaintext)
	if err != nil || bounded.N <= 0 || digest != expectedSHA256 {
		return 0, errors.New("snapshot decryption or integrity verification failed")
	}
	return size, nil
}
