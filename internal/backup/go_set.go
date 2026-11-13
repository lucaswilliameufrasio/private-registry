package backup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
)

const goSetDomain = "private-registry/go-backup-set/v1\x00"

// GoSet commits only to ZIP objects referenced by the Go catalog. The
// snapshot contains .mod bytes; this is not a complete installation manifest.
type GoSet GenericSet

type GoSetEnvelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func SignGoSet(set GoSet, key ed25519.PrivateKey) (GoSetEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize || !validGenericSet(GenericSet(set)) {
		return GoSetEnvelope{}, errors.New("Go backup set is invalid")
	}
	payload, err := json.Marshal(set)
	if err != nil || len(payload) > maxGenericSetBytes {
		return GoSetEnvelope{}, errors.New("Go backup set exceeds its encoding limit")
	}
	return GoSetEnvelope{Payload: payload, Signature: ed25519.Sign(key, append([]byte(goSetDomain), payload...))}, nil
}

// VerifyGoSetInventory requires independent trust and compares every ZIP with
// inventory derived from the authenticated snapshot. It does not prove
// freshness, storage availability or completeness of other formats.
func VerifyGoSetInventory(envelope GoSetEnvelope, key ed25519.PublicKey, installationID, backupID, snapshotSHA256 string, inventory []GenericObject) (GoSet, error) {
	set, err := VerifyGoSet(envelope, key, installationID, backupID, snapshotSHA256)
	if err != nil {
		return GoSet{}, err
	}
	if err := matchSetInventory(GenericSet(set), inventory); err != nil {
		return GoSet{}, err
	}
	return set, nil
}

// VerifyGoSet authenticates the format-specific set and independent context.
// Object inventory and each ciphertext must still be verified separately.
func VerifyGoSet(envelope GoSetEnvelope, key ed25519.PublicKey, installationID, backupID, snapshotSHA256 string) (GoSet, error) {
	if len(key) != ed25519.PublicKeySize || len(envelope.Signature) != ed25519.SignatureSize || len(envelope.Payload) == 0 || len(envelope.Payload) > maxGenericSetBytes {
		return GoSet{}, errors.New("Go backup set envelope is invalid")
	}
	if !ed25519.Verify(key, append([]byte(goSetDomain), envelope.Payload...), envelope.Signature) {
		return GoSet{}, errors.New("Go backup set signature rejected")
	}
	var set GoSet
	if err := json.Unmarshal(envelope.Payload, &set); err != nil || !validGenericSet(GenericSet(set)) {
		return GoSet{}, errors.New("Go backup set schema rejected")
	}
	canonical, err := json.Marshal(set)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return GoSet{}, errors.New("Go backup set encoding rejected")
	}
	if set.InstallationID != installationID || set.BackupID != backupID || set.SnapshotSHA256 != snapshotSHA256 {
		return GoSet{}, errors.New("Go backup set context rejected")
	}
	return set, nil
}
