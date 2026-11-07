package backup

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"filippo.io/age"
	"private-registry/internal/storage"
)

// RestoreReceiptedGenericObject verifies an independently trusted receipt and
// its entire ciphertext before decrypting to a second staging file. Neither
// staging file may be shared or modified concurrently; both must be empty and
// discarded after use. This verifies one object, not manifest completeness,
// freshness, credential revocation or installation-level recovery.
func RestoreReceiptedGenericObject(ctx context.Context, ciphertext io.Reader, envelope ObjectReceiptEnvelope, signer ed25519.PublicKey, installationID, backupID string, identity age.Identity, cipherStage, plainStage io.ReadWriteSeeker, destination storage.Driver) error {
	if ctx == nil || ciphertext == nil || identity == nil || cipherStage == nil || plainStage == nil || destination == nil {
		return errors.New("receipted object recovery parameters are invalid")
	}
	receipt, err := VerifyObjectReceipt(envelope, signer, installationID, backupID)
	if err != nil {
		return err
	}
	end, err := cipherStage.Seek(0, io.SeekEnd)
	if err != nil || end != 0 {
		return errors.New("receipted object recovery requires empty ciphertext staging")
	}
	if _, err := cipherStage.Seek(0, io.SeekStart); err != nil {
		return errors.New("ciphertext staging cannot be rewound")
	}
	hash := sha256.New()
	remaining := receipt.CipherBytes
	reader := &io.LimitedReader{R: ciphertext, N: receipt.CipherBytes + 1}
	buffer := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := reader.Read(buffer)
		if n > 0 {
			if int64(n) > remaining {
				return errors.New("backup ciphertext exceeds receipt size")
			}
			remaining -= int64(n)
			_, _ = hash.Write(buffer[:n])
			written, writeErr := cipherStage.Write(buffer[:n])
			if writeErr != nil || written != n {
				return errors.New("backup ciphertext could not be staged")
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return errors.New("backup ciphertext could not be read")
		}
		if n == 0 {
			return errors.New("backup ciphertext made no progress")
		}
	}
	if remaining != 0 || hex.EncodeToString(hash.Sum(nil)) != receipt.CipherSHA256 {
		return errors.New("backup ciphertext did not match receipt")
	}
	if _, err := cipherStage.Seek(0, io.SeekStart); err != nil {
		return errors.New("ciphertext staging cannot be rewound")
	}
	object := GenericObject{Key: storage.ObjectKey{WorkspaceID: receipt.WorkspaceID, SHA256: receipt.PlainSHA256}, Size: receipt.PlainBytes}
	return RestoreGenericObject(ctx, cipherStage, receipt.CipherBytes, object, identity, plainStage, destination)
}
