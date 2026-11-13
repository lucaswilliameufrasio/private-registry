package postgresbackup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const remoteReceiptDomain = "private-registry/phase0/postgresql-receipt/v1\x00"
const maxRemoteReceiptPayload = 4096
const maxRemotePlaintextBytes = 32 << 20
const maxRemoteCiphertextBytes = 34 << 20

// RemoteBackupReceipt is an experiment-only descriptor for one PostgreSQL
// logical dump. It is not the complete installation manifest or job receipt.
type RemoteBackupReceipt struct {
	Version        int    `json:"version"`
	Engine         string `json:"engine"`
	ToolsMajor     int    `json:"tools_major"`
	Installation   string `json:"installation"`
	Backup         string `json:"backup"`
	PlaintextSHA   string `json:"plaintext_sha256"`
	PlaintextSize  int64  `json:"plaintext_bytes"`
	CiphertextSHA  string `json:"ciphertext_sha256"`
	CiphertextSize int64  `json:"ciphertext_bytes"`
}

// RemoteBackupEnvelope deliberately carries no public trust key.
type RemoteBackupEnvelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func SignRemoteBackupReceipt(receipt RemoteBackupReceipt, key ed25519.PrivateKey) (RemoteBackupEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize || !validRemoteBackupReceipt(receipt) {
		return RemoteBackupEnvelope{}, errors.New("invalid PostgreSQL fixture signing inputs")
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return RemoteBackupEnvelope{}, err
	}
	return RemoteBackupEnvelope{Payload: payload, Signature: ed25519.Sign(key, remoteReceiptMessage(payload))}, nil
}

func VerifyRemoteBackupReceipt(envelope RemoteBackupEnvelope, key ed25519.PublicKey, installation, backup string, toolsMajor int) (RemoteBackupReceipt, error) {
	if len(key) != ed25519.PublicKeySize || len(envelope.Signature) != ed25519.SignatureSize || len(envelope.Payload) == 0 || len(envelope.Payload) > maxRemoteReceiptPayload {
		return RemoteBackupReceipt{}, errors.New("invalid PostgreSQL fixture receipt envelope")
	}
	if !ed25519.Verify(key, remoteReceiptMessage(envelope.Payload), envelope.Signature) {
		return RemoteBackupReceipt{}, errors.New("PostgreSQL receipt signature rejected")
	}
	var receipt RemoteBackupReceipt
	if err := json.Unmarshal(envelope.Payload, &receipt); err != nil || !validRemoteBackupReceipt(receipt) {
		return RemoteBackupReceipt{}, errors.New("PostgreSQL receipt schema rejected")
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return RemoteBackupReceipt{}, errors.New("PostgreSQL receipt encoding rejected")
	}
	if receipt.Installation != installation || receipt.Backup != backup || receipt.ToolsMajor != toolsMajor {
		return RemoteBackupReceipt{}, errors.New("PostgreSQL receipt context mismatch")
	}
	return receipt, nil
}

func remoteReceiptMessage(payload []byte) []byte {
	return append([]byte(remoteReceiptDomain), payload...)
}

func validRemoteBackupReceipt(receipt RemoteBackupReceipt) bool {
	return receipt.Version == 1 && receipt.Engine == "postgresql" && receipt.ToolsMajor >= 10 && receipt.ToolsMajor <= 99 &&
		validReceiptIdentifier(receipt.Installation) && validReceiptIdentifier(receipt.Backup) &&
		validReceiptDigest(receipt.PlaintextSHA) && validReceiptDigest(receipt.CiphertextSHA) &&
		receipt.PlaintextSize > 0 && receipt.PlaintextSize <= maxRemotePlaintextBytes &&
		receipt.CiphertextSize > 0 && receipt.CiphertextSize <= maxRemoteCiphertextBytes
}

func validReceiptIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func validReceiptDigest(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == 32 && hex.EncodeToString(digest) == value
}
