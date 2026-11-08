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

const genericSetDomain = "private-registry/generic-backup-set/v1\x00"
const maxGenericSetBytes = 4 << 20
const maxGenericSetObjects = 10000

// GenericSet is an experimental signed commitment to generic-object receipts
// and a snapshot digest. It is not a complete installation backup manifest.
// Objects must be sorted by workspace ID and plaintext SHA-256, without duplicates.
type GenericSet struct {
	Version        int             `json:"version"`
	InstallationID string          `json:"installation_id"`
	BackupID       string          `json:"backup_id"`
	SnapshotSHA256 string          `json:"snapshot_sha256"`
	Objects        []ObjectReceipt `json:"objects"`
}

type GenericSetEnvelope struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func SignGenericSet(set GenericSet, key ed25519.PrivateKey) (GenericSetEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize || !validGenericSet(set) {
		return GenericSetEnvelope{}, errors.New("generic backup set is invalid")
	}
	payload, err := json.Marshal(set)
	if err != nil || len(payload) > maxGenericSetBytes {
		return GenericSetEnvelope{}, errors.New("generic backup set exceeds its encoding limit")
	}
	message := append([]byte(genericSetDomain), payload...)
	return GenericSetEnvelope{Payload: payload, Signature: ed25519.Sign(key, message)}, nil
}

// VerifyGenericSet requires trust, backup identity and the independently
// computed plaintext snapshot digest from the recovery context. A valid set
// still requires verification of every ciphertext and of the installation's
// complete manifest and anti-rollback policy.
func VerifyGenericSet(envelope GenericSetEnvelope, key ed25519.PublicKey, installationID, backupID, snapshotSHA256 string) (GenericSet, error) {
	if len(key) != ed25519.PublicKeySize || len(envelope.Signature) != ed25519.SignatureSize || len(envelope.Payload) == 0 || len(envelope.Payload) > maxGenericSetBytes {
		return GenericSet{}, errors.New("generic backup set envelope is invalid")
	}
	if !ed25519.Verify(key, append([]byte(genericSetDomain), envelope.Payload...), envelope.Signature) {
		return GenericSet{}, errors.New("generic backup set signature rejected")
	}
	var set GenericSet
	if err := json.Unmarshal(envelope.Payload, &set); err != nil || !validGenericSet(set) {
		return GenericSet{}, errors.New("generic backup set schema rejected")
	}
	canonical, err := json.Marshal(set)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return GenericSet{}, errors.New("generic backup set encoding rejected")
	}
	if set.InstallationID != installationID || set.BackupID != backupID || set.SnapshotSHA256 != snapshotSHA256 {
		return GenericSet{}, errors.New("generic backup set context rejected")
	}
	return set, nil
}

// VerifyGenericSetInventory authenticates the set and compares every generic
// reference against inventory derived from the already verified snapshot.
func VerifyGenericSetInventory(envelope GenericSetEnvelope, key ed25519.PublicKey, installationID, backupID, snapshotSHA256 string, inventory []GenericObject) (GenericSet, error) {
	set, err := VerifyGenericSet(envelope, key, installationID, backupID, snapshotSHA256)
	if err != nil {
		return GenericSet{}, err
	}
	if err := matchSetInventory(set, inventory); err != nil {
		return GenericSet{}, err
	}
	return set, nil
}

func matchSetInventory(set GenericSet, inventory []GenericObject) error {
	if len(inventory) != len(set.Objects) || len(inventory) > maxGenericSetObjects {
		return errors.New("backup set does not match inventory")
	}
	expected := make(map[storage.ObjectKey]int64, len(inventory))
	for _, object := range inventory {
		canonical, err := storage.NewObjectKey(object.Key.WorkspaceID, object.Key.SHA256)
		if err != nil || canonical != object.Key || object.Size < 0 || object.Size > 1<<30 {
			return errors.New("backup inventory contains an invalid object")
		}
		if _, exists := expected[object.Key]; exists {
			return errors.New("backup inventory contains a duplicate object")
		}
		expected[object.Key] = object.Size
	}
	for _, object := range set.Objects {
		objectKey := storage.ObjectKey{WorkspaceID: object.WorkspaceID, SHA256: object.PlainSHA256}
		if size, exists := expected[objectKey]; !exists || size != object.PlainBytes {
			return errors.New("backup set does not match inventory")
		}
		delete(expected, objectKey)
	}
	if len(expected) != 0 {
		return errors.New("backup set does not match inventory")
	}
	return nil
}

func validGenericSet(set GenericSet) bool {
	if set.Version != 1 || set.Objects == nil || len(set.Objects) > maxGenericSetObjects {
		return false
	}
	digest, err := hex.DecodeString(set.SnapshotSHA256)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != set.SnapshotSHA256 {
		return false
	}
	installation, installationErr := uuid.Parse(set.InstallationID)
	backupID, backupErr := uuid.Parse(set.BackupID)
	if installationErr != nil || installation.String() != set.InstallationID || backupErr != nil || backupID.String() != set.BackupID {
		return false
	}
	previousWorkspace, previousDigest := "", ""
	for _, object := range set.Objects {
		if !validObjectReceipt(object) || object.InstallationID != set.InstallationID || object.BackupID != set.BackupID {
			return false
		}
		if object.WorkspaceID < previousWorkspace || (object.WorkspaceID == previousWorkspace && object.PlainSHA256 <= previousDigest) {
			return false
		}
		previousWorkspace, previousDigest = object.WorkspaceID, object.PlainSHA256
	}
	return true
}
