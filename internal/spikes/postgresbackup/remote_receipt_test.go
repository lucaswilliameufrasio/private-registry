package postgresbackup

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func fixtureRemoteReceipt() RemoteBackupReceipt {
	return RemoteBackupReceipt{
		Version: 1, Engine: "postgresql", ToolsMajor: 18, Installation: "fixture", Backup: "backup-1",
		PlaintextSHA: strings.Repeat("a", 64), PlaintextSize: 1024,
		CiphertextSHA: strings.Repeat("b", 64), CiphertextSize: 1200,
	}
}

func TestRemotePostgresReceiptSignatureAndContext(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignRemoteBackupReceipt(fixtureRemoteReceipt(), private)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := VerifyRemoteBackupReceipt(envelope, public, "fixture", "backup-1", 18); err != nil || receipt != fixtureRemoteReceipt() {
		t.Fatal("valid PostgreSQL receipt failed:", err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"tampered", "wrong_key", "unsigned", "wrong_domain", "installation", "backup", "tools_major", "oversized", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			attempt := RemoteBackupEnvelope{Payload: append([]byte(nil), envelope.Payload...), Signature: append([]byte(nil), envelope.Signature...)}
			key, installation, backup, toolsMajor := public, "fixture", "backup-1", 18
			switch scenario {
			case "tampered":
				attempt.Payload[len(attempt.Payload)-2] ^= 1
			case "wrong_key":
				key = other
			case "unsigned":
				attempt.Signature = nil
			case "wrong_domain":
				attempt.Signature = ed25519.Sign(private, attempt.Payload)
			case "installation":
				installation = "other"
			case "backup":
				backup = "backup-2"
			case "tools_major":
				toolsMajor = 17
			case "oversized":
				attempt.Payload = make([]byte, maxRemoteReceiptPayload+1)
			case "empty":
				attempt.Payload = nil
			}
			if _, err := VerifyRemoteBackupReceipt(attempt, key, installation, backup, toolsMajor); err == nil {
				t.Fatal("untrusted or mismatched PostgreSQL receipt accepted")
			}
		})
	}
	if _, err := SignRemoteBackupReceipt(fixtureRemoteReceipt(), nil); err == nil {
		t.Fatal("invalid private key accepted")
	}
}

func TestSignedPostgresReceiptRejectsInvalidCanonicalProfiles(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"engine", "tools", "path_id", "digest", "size", "unknown", "duplicate", "trailing", "malformed"} {
		t.Run(scenario, func(t *testing.T) {
			receipt := fixtureRemoteReceipt()
			switch scenario {
			case "engine":
				receipt.Engine = "sqlite"
			case "tools":
				receipt.ToolsMajor = 9
			case "path_id":
				receipt.Backup = "../backup"
			case "digest":
				receipt.CiphertextSHA = "invalid"
			case "size":
				receipt.PlaintextSize = maxRemotePlaintextBytes + 1
			}
			payload, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "unknown":
				payload = append(payload[:len(payload)-1], []byte(`,"extra":true}`)...)
			case "duplicate":
				payload = append(payload[:len(payload)-1], []byte(`,"backup":"backup-1"}`)...)
			case "trailing":
				payload = append(payload, []byte(" {}")...)
			case "malformed":
				payload = []byte("{")
			}
			envelope := RemoteBackupEnvelope{Payload: payload, Signature: ed25519.Sign(private, remoteReceiptMessage(payload))}
			if _, err := VerifyRemoteBackupReceipt(envelope, public, "fixture", "backup-1", 18); err == nil {
				t.Fatal("invalid signed PostgreSQL receipt profile accepted")
			}
			if !validRemoteBackupReceipt(receipt) {
				if _, err := SignRemoteBackupReceipt(receipt, private); err == nil {
					t.Fatal("invalid PostgreSQL receipt profile signed")
				}
			}
		})
	}
}
