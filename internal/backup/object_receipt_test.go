package backup

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
)

func TestObjectReceiptRequiresIndependentTrustAndContext(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain := sha256.Sum256([]byte("synthetic plaintext"))
	cipher := sha256.Sum256([]byte("synthetic ciphertext"))
	receipt := ObjectReceipt{Version: 1, InstallationID: uuid.NewString(), BackupID: uuid.NewString(), WorkspaceID: uuid.NewString(), PlainSHA256: hex.EncodeToString(plain[:]), PlainBytes: 19, CipherSHA256: hex.EncodeToString(cipher[:]), CipherBytes: 100}
	envelope, err := SignObjectReceipt(receipt, private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyObjectReceipt(envelope, public, receipt.InstallationID, receipt.BackupID)
	if err != nil || verified != receipt {
		t.Fatalf("verify valid receipt: %v", err)
	}
	if _, err := VerifyObjectReceipt(envelope, otherPublic, receipt.InstallationID, receipt.BackupID); err == nil {
		t.Fatal("receipt accepted under untrusted key")
	}
	if _, err := VerifyObjectReceipt(envelope, public, receipt.InstallationID, uuid.NewString()); err == nil {
		t.Fatal("receipt accepted for another backup")
	}
	modified := ObjectReceiptEnvelope{Payload: append([]byte(nil), envelope.Payload...), Signature: envelope.Signature}
	modified.Payload[10] ^= 1
	if _, err := VerifyObjectReceipt(modified, public, receipt.InstallationID, receipt.BackupID); err == nil {
		t.Fatal("modified receipt accepted")
	}
	noncanonical := append(append([]byte(nil), envelope.Payload[:len(envelope.Payload)-1]...), []byte(",\"extra\":true}")...)
	message := append([]byte(objectReceiptDomain), noncanonical...)
	modified = ObjectReceiptEnvelope{Payload: noncanonical, Signature: ed25519.Sign(private, message)}
	if _, err := VerifyObjectReceipt(modified, public, receipt.InstallationID, receipt.BackupID); err == nil {
		t.Fatal("signed receipt with unknown field accepted")
	}
	invalid := receipt
	invalid.CipherBytes = 0
	if _, err := SignObjectReceipt(invalid, private); err == nil {
		t.Fatal("invalid receipt was signed")
	}
}
