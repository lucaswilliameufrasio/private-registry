package backup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
)

const cargoSetDomain = "private-registry/cargo-backup-set/v1\x00"

// CargoSet covers only archives referenced by a Cargo snapshot inventory. It
// is not a complete installation manifest or a freshness guarantee.
type CargoSet GenericSet

type CargoSetEnvelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func SignCargoSet(set CargoSet, key ed25519.PrivateKey) (CargoSetEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize || !validGenericSet(GenericSet(set)) {
		return CargoSetEnvelope{}, errors.New("Cargo backup set is invalid")
	}
	payload, err := json.Marshal(set)
	if err != nil || len(payload) > maxGenericSetBytes {
		return CargoSetEnvelope{}, errors.New("Cargo backup set exceeds its encoding limit")
	}
	return CargoSetEnvelope{Payload: payload, Signature: ed25519.Sign(key, append([]byte(cargoSetDomain), payload...))}, nil
}

// VerifyCargoSet verifies a format-specific set against independently supplied
// trust and snapshot context. It does not prove availability or completeness.
func VerifyCargoSet(envelope CargoSetEnvelope, key ed25519.PublicKey, installationID, backupID, snapshotSHA256 string) (CargoSet, error) {
	if len(key) != ed25519.PublicKeySize || len(envelope.Signature) != ed25519.SignatureSize || len(envelope.Payload) == 0 || len(envelope.Payload) > maxGenericSetBytes {
		return CargoSet{}, errors.New("Cargo backup set envelope is invalid")
	}
	if !ed25519.Verify(key, append([]byte(cargoSetDomain), envelope.Payload...), envelope.Signature) {
		return CargoSet{}, errors.New("Cargo backup set signature rejected")
	}
	var set CargoSet
	if err := json.Unmarshal(envelope.Payload, &set); err != nil || !validGenericSet(GenericSet(set)) {
		return CargoSet{}, errors.New("Cargo backup set schema rejected")
	}
	canonical, err := json.Marshal(set)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return CargoSet{}, errors.New("Cargo backup set encoding rejected")
	}
	if set.InstallationID != installationID || set.BackupID != backupID || set.SnapshotSHA256 != snapshotSHA256 {
		return CargoSet{}, errors.New("Cargo backup set context rejected")
	}
	return set, nil
}

func VerifyCargoSetInventory(envelope CargoSetEnvelope, key ed25519.PublicKey, installationID, backupID, snapshotSHA256 string, inventory []GenericObject) (CargoSet, error) {
	set, err := VerifyCargoSet(envelope, key, installationID, backupID, snapshotSHA256)
	if err != nil {
		return CargoSet{}, err
	}
	if err := matchSetInventory(GenericSet(set), inventory); err != nil {
		return CargoSet{}, err
	}
	return set, nil
}
