package backup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
)

const npmSetDomain = "private-registry/npm-backup-set/v1\x00"

// NPMSet covers only archives referenced by a NPM snapshot inventory. It
// is not a complete installation manifest or a freshness guarantee.
type NPMSet GenericSet

type NPMSetEnvelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func SignNPMSet(set NPMSet, key ed25519.PrivateKey) (NPMSetEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize || !validGenericSet(GenericSet(set)) {
		return NPMSetEnvelope{}, errors.New("NPM backup set is invalid")
	}
	payload, err := json.Marshal(set)
	if err != nil || len(payload) > maxGenericSetBytes {
		return NPMSetEnvelope{}, errors.New("NPM backup set exceeds its encoding limit")
	}
	return NPMSetEnvelope{Payload: payload, Signature: ed25519.Sign(key, append([]byte(npmSetDomain), payload...))}, nil
}

// VerifyNPMSet verifies a format-specific set against independently supplied
// trust and snapshot context. It does not prove availability or completeness.
func VerifyNPMSet(envelope NPMSetEnvelope, key ed25519.PublicKey, installationID, backupID, snapshotSHA256 string) (NPMSet, error) {
	if len(key) != ed25519.PublicKeySize || len(envelope.Signature) != ed25519.SignatureSize || len(envelope.Payload) == 0 || len(envelope.Payload) > maxGenericSetBytes {
		return NPMSet{}, errors.New("NPM backup set envelope is invalid")
	}
	if !ed25519.Verify(key, append([]byte(npmSetDomain), envelope.Payload...), envelope.Signature) {
		return NPMSet{}, errors.New("NPM backup set signature rejected")
	}
	var set NPMSet
	if err := json.Unmarshal(envelope.Payload, &set); err != nil || !validGenericSet(GenericSet(set)) {
		return NPMSet{}, errors.New("NPM backup set schema rejected")
	}
	canonical, err := json.Marshal(set)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return NPMSet{}, errors.New("NPM backup set encoding rejected")
	}
	if set.InstallationID != installationID || set.BackupID != backupID || set.SnapshotSHA256 != snapshotSHA256 {
		return NPMSet{}, errors.New("NPM backup set context rejected")
	}
	return set, nil
}

func VerifyNPMSetInventory(envelope NPMSetEnvelope, key ed25519.PublicKey, installationID, backupID, snapshotSHA256 string, inventory []GenericObject) (NPMSet, error) {
	set, err := VerifyNPMSet(envelope, key, installationID, backupID, snapshotSHA256)
	if err != nil {
		return NPMSet{}, err
	}
	if err := matchSetInventory(GenericSet(set), inventory); err != nil {
		return NPMSet{}, err
	}
	return set, nil
}
