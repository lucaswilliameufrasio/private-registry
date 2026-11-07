package backup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"private-registry/internal/storage"
)

const objectReceiptDomain = "private-registry/generic-backup-object-receipt/v1\x00"
const maxObjectReceiptBytes = 2048

// ObjectReceipt authenticates one generic object, not the completeness,
// freshness, ordering or recoverability of an installation backup.
type ObjectReceipt struct {
	Version        int    `json:"version"`
	InstallationID string `json:"installation_id"`
	BackupID       string `json:"backup_id"`
	WorkspaceID    string `json:"workspace_id"`
	PlainSHA256    string `json:"plain_sha256"`
	PlainBytes     int64  `json:"plain_bytes"`
	CipherSHA256   string `json:"cipher_sha256"`
	CipherBytes    int64  `json:"cipher_bytes"`
}

type ObjectReceiptEnvelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// SignObjectReceipt signs a strict encoding. The private key must be separate
// from age recovery identities and be managed by the caller.
func SignObjectReceipt(receipt ObjectReceipt, key ed25519.PrivateKey) (ObjectReceiptEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize || !validObjectReceipt(receipt) {
		return ObjectReceiptEnvelope{}, errors.New("generic backup object receipt is invalid")
	}
	payload, err := json.Marshal(receipt)
	if err != nil || len(payload) > maxObjectReceiptBytes {
		return ObjectReceiptEnvelope{}, errors.New("generic backup object receipt could not be encoded")
	}
	message := append([]byte(objectReceiptDomain), payload...)
	return ObjectReceiptEnvelope{Payload: payload, Signature: ed25519.Sign(key, message)}, nil
}

// VerifyObjectReceipt requires independently supplied trust and exact expected
// context. The caller must still authenticate a complete backup manifest and
// guard against stale receipts and replay across recovery points.
func VerifyObjectReceipt(envelope ObjectReceiptEnvelope, key ed25519.PublicKey, installationID, backupID string) (ObjectReceipt, error) {
	if len(key) != ed25519.PublicKeySize || len(envelope.Signature) != ed25519.SignatureSize || len(envelope.Payload) == 0 || len(envelope.Payload) > maxObjectReceiptBytes {
		return ObjectReceipt{}, errors.New("generic backup object receipt envelope is invalid")
	}
	message := append([]byte(objectReceiptDomain), envelope.Payload...)
	if !ed25519.Verify(key, message, envelope.Signature) {
		return ObjectReceipt{}, errors.New("generic backup object receipt signature rejected")
	}
	var receipt ObjectReceipt
	if err := json.Unmarshal(envelope.Payload, &receipt); err != nil || !validObjectReceipt(receipt) {
		return ObjectReceipt{}, errors.New("generic backup object receipt schema rejected")
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return ObjectReceipt{}, errors.New("generic backup object receipt encoding rejected")
	}
	if receipt.InstallationID != installationID || receipt.BackupID != backupID {
		return ObjectReceipt{}, errors.New("generic backup object receipt context rejected")
	}
	return receipt, nil
}

func validObjectReceipt(receipt ObjectReceipt) bool {
	installationID, installationErr := uuid.Parse(receipt.InstallationID)
	backupID, backupErr := uuid.Parse(receipt.BackupID)
	key, keyErr := storage.NewObjectKey(receipt.WorkspaceID, receipt.PlainSHA256)
	cipherDigest, digestErr := hex.DecodeString(receipt.CipherSHA256)
	return receipt.Version == 1 && installationErr == nil && installationID.String() == receipt.InstallationID &&
		backupErr == nil && backupID.String() == receipt.BackupID && keyErr == nil &&
		key.WorkspaceID == receipt.WorkspaceID && key.SHA256 == receipt.PlainSHA256 &&
		receipt.PlainBytes >= 0 && receipt.PlainBytes <= 1<<30 && digestErr == nil && len(cipherDigest) == 32 &&
		hex.EncodeToString(cipherDigest) == receipt.CipherSHA256 && receipt.CipherBytes > 0 && receipt.CipherBytes <= 2<<30
}
