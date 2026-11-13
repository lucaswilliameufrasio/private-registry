package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"filippo.io/age"
)

// EncryptedSnapshot describes one successfully encrypted stable snapshot.
// It is not a signed manifest or evidence of remote storage or freshness.
type EncryptedSnapshot struct {
	PlainSHA256  string
	PlainBytes   int64
	CipherSHA256 string
	CipherBytes  int64
}

// EncryptSnapshot encrypts a stable, caller-provided snapshot in a bounded
// stream. The caller must create a consistent snapshot, enforce a hard staging
// quota, and discard all output after any error. Context cancellation cannot
// interrupt an arbitrary blocked reader or writer. This does not pin objects,
// authenticate the snapshot's origin or publish an installation backup.
func EncryptSnapshot(ctx context.Context, snapshot io.Reader, destination io.Writer, maxPlaintext, maxCiphertext int64, recipient age.Recipient) (EncryptedSnapshot, error) {
	if ctx == nil || snapshot == nil || destination == nil || recipient == nil || maxPlaintext < 1 || maxPlaintext > 1<<40 || maxCiphertext < 1 || maxCiphertext > 1<<40 {
		return EncryptedSnapshot{}, errors.New("snapshot encryption parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return EncryptedSnapshot{}, errors.New("snapshot encryption requires a deadline")
	}
	if err := ctx.Err(); err != nil {
		return EncryptedSnapshot{}, err
	}
	hash := sha256.New()
	bounded := &captureBoundedWriter{destination: io.MultiWriter(destination, hash), remaining: maxCiphertext}
	writer, err := age.Encrypt(bounded, recipient)
	if err != nil {
		return EncryptedSnapshot{}, errors.New("snapshot encryption could not begin")
	}
	digest, size, digestErr := DigestSnapshot(ctx, io.TeeReader(snapshot, writer), maxPlaintext)
	closeErr := writer.Close()
	if digestErr != nil || closeErr != nil {
		return EncryptedSnapshot{}, errors.New("snapshot encryption did not complete")
	}
	if err := ctx.Err(); err != nil {
		return EncryptedSnapshot{}, err
	}
	return EncryptedSnapshot{PlainSHA256: digest, PlainBytes: size, CipherSHA256: hex.EncodeToString(hash.Sum(nil)), CipherBytes: bounded.written}, nil
}
