package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"

	"filippo.io/age"
	"private-registry/internal/storage"
)

// CapturedGenericSet is evidence for generic objects only. It is not a complete
// installation manifest and must never be used alone as a completed backup.
type CapturedGenericSet struct {
	Set      GenericSetEnvelope
	Receipts []ObjectReceiptEnvelope
}

// CaptureGenericSet encrypts inventoried objects to private staging, stores and
// fully verifies each ciphertext, then signs their generic-only set. The caller
// must hold a trustworthy database snapshot and protect source objects from GC
// for the entire operation. Staging must be exclusive, empty, bounded, and
// removed on Close. Failures can leave orphaned destination objects; this
// function neither publishes a completed backup nor deletes/reconciles them.
func CaptureGenericSet(ctx context.Context, trusted GenericSetRecovery, source, destination storage.Driver, recipient age.Recipient, signer ed25519.PrivateKey, maxCiphertext int64, newStage func() (RecoveryStage, error)) (CapturedGenericSet, error) {
	if ctx == nil || source == nil || destination == nil || recipient == nil || newStage == nil || maxCiphertext < 1 || maxCiphertext > 2<<30 || len(signer) != ed25519.PrivateKeySize || len(trusted.Inventory) > maxGenericSetObjects {
		return CapturedGenericSet{}, errors.New("generic backup capture parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return CapturedGenericSet{}, errors.New("generic backup capture requires a deadline")
	}
	if len(trusted.Signer) != ed25519.PublicKeySize || !bytes.Equal(signer.Public().(ed25519.PublicKey), trusted.Signer) {
		return CapturedGenericSet{}, errors.New("generic backup signer does not match configured trust")
	}
	if err := ctx.Err(); err != nil {
		return CapturedGenericSet{}, err
	}
	set := GenericSet{Version: 1, InstallationID: trusted.InstallationID, BackupID: trusted.BackupID, SnapshotSHA256: trusted.SnapshotSHA256, Objects: []ObjectReceipt{}}
	if !validGenericSet(set) {
		return CapturedGenericSet{}, errors.New("generic backup capture context is invalid")
	}
	inventory := append([]GenericObject(nil), trusted.Inventory...)
	sort.Slice(inventory, func(i, j int) bool {
		if inventory[i].Key.WorkspaceID != inventory[j].Key.WorkspaceID {
			return inventory[i].Key.WorkspaceID < inventory[j].Key.WorkspaceID
		}
		return inventory[i].Key.SHA256 < inventory[j].Key.SHA256
	})
	for i, object := range inventory {
		canonical, err := storage.NewObjectKey(object.Key.WorkspaceID, object.Key.SHA256)
		if err != nil || canonical != object.Key || object.Size < 0 || object.Size > 1<<30 || (i > 0 && inventory[i-1].Key == object.Key) {
			return CapturedGenericSet{}, errors.New("generic backup capture inventory is invalid")
		}
	}
	receipts := make([]ObjectReceiptEnvelope, 0, len(inventory))
	for _, object := range inventory {
		receipt, envelope, err := captureGenericObject(ctx, trusted, object, source, destination, recipient, signer, maxCiphertext, newStage)
		if err != nil {
			return CapturedGenericSet{}, err
		}
		set.Objects = append(set.Objects, receipt)
		receipts = append(receipts, envelope)
	}
	signed, err := SignGenericSet(set, signer)
	if err != nil {
		return CapturedGenericSet{}, err
	}
	return CapturedGenericSet{Set: signed, Receipts: receipts}, nil
}

func captureGenericObject(ctx context.Context, trusted GenericSetRecovery, object GenericObject, source, destination storage.Driver, recipient age.Recipient, signer ed25519.PrivateKey, maxCiphertext int64, newStage func() (RecoveryStage, error)) (receipt ObjectReceipt, envelope ObjectReceiptEnvelope, retErr error) {
	stage, err := newStage()
	if err != nil || stage == nil {
		if stage != nil {
			_ = stage.Close()
		}
		return receipt, envelope, errors.New("generic backup staging could not be created")
	}
	defer func() {
		if err := stage.Close(); err != nil {
			receipt = ObjectReceipt{}
			envelope = ObjectReceiptEnvelope{}
			retErr = errors.Join(retErr, errors.New("generic backup staging could not be removed"))
		}
	}()
	if end, err := stage.Seek(0, io.SeekEnd); err != nil || end != 0 {
		return receipt, envelope, errors.New("generic backup staging must be empty")
	}
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		return receipt, envelope, errors.New("generic backup staging cannot be rewound")
	}
	hash := sha256.New()
	writer := &captureBoundedWriter{destination: io.MultiWriter(stage, hash), remaining: maxCiphertext}
	if err := EncryptGenericObject(ctx, source, object, writer, recipient); err != nil {
		return receipt, envelope, err
	}
	cipherDigest := hex.EncodeToString(hash.Sum(nil))
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		return receipt, envelope, errors.New("generic backup staging cannot be rewound")
	}
	stored, err := destination.Put(ctx, object.Key.WorkspaceID, stage, writer.written)
	if err != nil {
		return receipt, envelope, errors.New("generic backup ciphertext could not be stored")
	}
	expected := GenericObject{Key: storage.ObjectKey{WorkspaceID: object.Key.WorkspaceID, SHA256: cipherDigest}, Size: writer.written}
	if stored.Key != expected.Key || stored.Size != expected.Size {
		return receipt, envelope, errors.New("stored generic backup ciphertext metadata is invalid")
	}
	if err := copyBoundedObject(ctx, destination, expected, io.Discard, maxCiphertext); err != nil {
		return receipt, envelope, errors.New("stored generic backup ciphertext could not be verified")
	}
	receipt = ObjectReceipt{Version: 1, InstallationID: trusted.InstallationID, BackupID: trusted.BackupID, WorkspaceID: object.Key.WorkspaceID, PlainSHA256: object.Key.SHA256, PlainBytes: object.Size, CipherSHA256: cipherDigest, CipherBytes: writer.written}
	envelope, err = SignObjectReceipt(receipt, signer)
	if err != nil {
		return ObjectReceipt{}, ObjectReceiptEnvelope{}, err
	}
	return receipt, envelope, nil
}

type captureBoundedWriter struct {
	destination io.Writer
	remaining   int64
	written     int64
}

func (w *captureBoundedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, errors.New("generic backup ciphertext exceeds its limit")
	}
	n, err := w.destination.Write(data)
	w.remaining -= int64(n)
	w.written += int64(n)
	return n, err
}
