// Package backupreceipt is a phase-0 signed single-snapshot receipt experiment.
// It is not the production installation manifest or its trust/rotation policy.
package backupreceipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const domain = "private-registry/phase0/sqlite-receipt/v1\x00"
const maxPayload = 4096

type Receipt struct {
	Version      int    `json:"version"`
	Installation string `json:"installation"`
	Backup       string `json:"backup"`
	PlainSHA     string `json:"plain_sha256"`
	CipherSHA    string `json:"cipher_sha256"`
	CipherBytes  int64  `json:"cipher_bytes"`
}

// Envelope never supplies the trusted verification key. That key and expected
// context must come from an independent channel chosen by the verifier.
type Envelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func Sign(receipt Receipt, key ed25519.PrivateKey) (Envelope, error) {
	if len(key) != ed25519.PrivateKeySize || !valid(receipt) {
		return Envelope{}, errors.New("invalid fixture signing inputs")
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Payload: payload, Signature: ed25519.Sign(key, message(payload))}, nil
}

func Verify(envelope Envelope, key ed25519.PublicKey, installation, backup string) (Receipt, error) {
	if len(key) != ed25519.PublicKeySize || len(envelope.Signature) != ed25519.SignatureSize || len(envelope.Payload) == 0 || len(envelope.Payload) > maxPayload {
		return Receipt{}, errors.New("invalid fixture signed envelope")
	}
	if !ed25519.Verify(key, message(envelope.Payload), envelope.Signature) {
		return Receipt{}, errors.New("receipt signature rejected")
	}
	var receipt Receipt
	if err := json.Unmarshal(envelope.Payload, &receipt); err != nil || !valid(receipt) {
		return Receipt{}, errors.New("receipt schema rejected")
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		// Exact profile rejects duplicate/unknown fields, trailing data, alias
		// representations and ambiguous inputs, even when signed by a known key.
		return Receipt{}, errors.New("receipt encoding rejected")
	}
	if receipt.Installation != installation || receipt.Backup != backup {
		return Receipt{}, errors.New("receipt context mismatch")
	}
	return receipt, nil
}

func message(payload []byte) []byte {
	return append([]byte(domain), payload...)
}

func valid(receipt Receipt) bool {
	return receipt.Version == 1 && identifier(receipt.Installation) && identifier(receipt.Backup) &&
		digest(receipt.PlainSHA) && digest(receipt.CipherSHA) && receipt.CipherBytes > 0 && receipt.CipherBytes <= 2<<20
}

func identifier(value string) bool {
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

func digest(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 32 && hex.EncodeToString(data) == value
}
