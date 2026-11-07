package backup

import (
	"crypto/ed25519"
	"errors"

	"github.com/google/uuid"
	"private-registry/internal/storage"
)

// VerifyGenericReceipts compares signed receipts with a complete generic
// inventory from a trusted snapshot. It rejects missing, extra, duplicated or
// size-mismatched objects. This does not authenticate the snapshot, verify
// ciphertext availability, prevent rollback or cover any other format.
func VerifyGenericReceipts(inventory []GenericObject, envelopes []ObjectReceiptEnvelope, signer ed25519.PublicKey, installationID, backupID string, maxObjects int) ([]ObjectReceipt, error) {
	if maxObjects < 1 || maxObjects > 1000000 || len(inventory) > maxObjects || len(envelopes) > maxObjects || len(inventory) != len(envelopes) {
		return nil, errors.New("generic backup receipt inventory is incomplete or exceeds its limit")
	}
	installation, installationErr := uuid.Parse(installationID)
	backupIDParsed, backupErr := uuid.Parse(backupID)
	if len(signer) != ed25519.PublicKeySize || installationErr != nil || installation.String() != installationID || backupErr != nil || backupIDParsed.String() != backupID {
		return nil, errors.New("generic backup receipt trust or context is invalid")
	}
	expected := make(map[storage.ObjectKey]int64, len(inventory))
	for _, object := range inventory {
		key, err := storage.NewObjectKey(object.Key.WorkspaceID, object.Key.SHA256)
		if err != nil || key != object.Key || object.Size < 0 || object.Size > 1<<30 {
			return nil, errors.New("generic backup inventory contains an invalid object")
		}
		if _, exists := expected[key]; exists {
			return nil, errors.New("generic backup inventory contains a duplicate object")
		}
		expected[key] = object.Size
	}
	verified := make([]ObjectReceipt, 0, len(envelopes))
	for _, envelope := range envelopes {
		receipt, err := VerifyObjectReceipt(envelope, signer, installationID, backupID)
		if err != nil {
			return nil, err
		}
		key := storage.ObjectKey{WorkspaceID: receipt.WorkspaceID, SHA256: receipt.PlainSHA256}
		size, exists := expected[key]
		if !exists || size != receipt.PlainBytes {
			return nil, errors.New("generic backup receipt does not match inventory")
		}
		delete(expected, key)
		verified = append(verified, receipt)
	}
	if len(expected) != 0 {
		return nil, errors.New("generic backup inventory has missing receipts")
	}
	return verified, nil
}
