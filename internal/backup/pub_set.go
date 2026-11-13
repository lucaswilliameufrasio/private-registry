package backup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
)

const pubSetDomain = "private-registry/pub-backup-set/v1\x00"

// PubSet covers only archives referenced by a Pub snapshot inventory. It
// is not a complete installation manifest or a freshness guarantee.
type PubSet GenericSet

type PubSetEnvelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func SignPubSet(set PubSet, key ed25519.PrivateKey) (PubSetEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize || !validGenericSet(GenericSet(set)) {
		return PubSetEnvelope{}, errors.New("Pub backup set is invalid")
	}
	payload, err := json.Marshal(set)
	if err != nil || len(payload) > maxGenericSetBytes {
		return PubSetEnvelope{}, errors.New("Pub backup set exceeds its encoding limit")
	}
	return PubSetEnvelope{Payload: payload, Signature: ed25519.Sign(key, append([]byte(pubSetDomain), payload...))}, nil
}

// VerifyPubSet verifies a format-specific set against independently supplied
// trust and snapshot context. It does not prove availability or completeness.
func VerifyPubSet(envelope PubSetEnvelope, key ed25519.PublicKey, installationID, backupID, snapshotSHA256 string) (PubSet, error) {
	if len(key) != ed25519.PublicKeySize || len(envelope.Signature) != ed25519.SignatureSize || len(envelope.Payload) == 0 || len(envelope.Payload) > maxGenericSetBytes {
		return PubSet{}, errors.New("Pub backup set envelope is invalid")
	}
	if !ed25519.Verify(key, append([]byte(pubSetDomain), envelope.Payload...), envelope.Signature) {
		return PubSet{}, errors.New("Pub backup set signature rejected")
	}
	var set PubSet
	if err := json.Unmarshal(envelope.Payload, &set); err != nil || !validGenericSet(GenericSet(set)) {
		return PubSet{}, errors.New("Pub backup set schema rejected")
	}
	canonical, err := json.Marshal(set)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return PubSet{}, errors.New("Pub backup set encoding rejected")
	}
	if set.InstallationID != installationID || set.BackupID != backupID || set.SnapshotSHA256 != snapshotSHA256 {
		return PubSet{}, errors.New("Pub backup set context rejected")
	}
	return set, nil
}

func VerifyPubSetInventory(envelope PubSetEnvelope, key ed25519.PublicKey, installationID, backupID, snapshotSHA256 string, inventory []GenericObject) (PubSet, error) {
	set, err := VerifyPubSet(envelope, key, installationID, backupID, snapshotSHA256)
	if err != nil {
		return PubSet{}, err
	}
	if err := matchSetInventory(GenericSet(set), inventory); err != nil {
		return PubSet{}, err
	}
	return set, nil
}
