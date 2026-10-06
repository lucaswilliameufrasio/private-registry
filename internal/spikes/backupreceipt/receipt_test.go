package backupreceipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func fixture() Receipt {
	return Receipt{Version: 1, Installation: "fixture", Backup: "backup-1", PlainSHA: strings.Repeat("a", 64), CipherSHA: strings.Repeat("b", 64), CipherBytes: 1024}
}

func TestSignedReceiptTrustAndContext(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Sign(fixture(), private)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Verify(envelope, public, "fixture", "backup-1"); err != nil || got != fixture() {
		t.Fatal("valid receipt failed:", err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"tampered", "wrong_key", "unsigned", "wrong_domain", "installation", "backup", "oversized", "empty", "bad_key"} {
		t.Run(scenario, func(t *testing.T) {
			attempt := Envelope{Payload: append([]byte(nil), envelope.Payload...), Signature: append([]byte(nil), envelope.Signature...)}
			key, installation, backup := public, "fixture", "backup-1"
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
				installation = "another"
			case "backup":
				backup = "backup-2"
			case "oversized":
				attempt.Payload = make([]byte, maxPayload+1)
			case "empty":
				attempt.Payload = nil
			case "bad_key":
				key = nil
			}
			if _, err := Verify(attempt, key, installation, backup); err == nil {
				t.Fatal("untrusted/mismatched receipt accepted")
			}
		})
	}
	if _, err := Sign(fixture(), nil); err == nil {
		t.Fatal("invalid private key accepted")
	}
}

func TestSignedButInvalidReceiptProfile(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"version", "invalid_id", "long_id", "empty_id", "digest", "uppercase_digest", "zero_size", "negative_size", "oversized_archive", "unknown_field", "duplicate_field", "trailing", "malformed"} {
		t.Run(scenario, func(t *testing.T) {
			receipt := fixture()
			switch scenario {
			case "version":
				receipt.Version = 2
			case "invalid_id":
				receipt.Installation = "../fixture"
			case "long_id":
				receipt.Backup = strings.Repeat("x", 129)
			case "empty_id":
				receipt.Backup = ""
			case "digest":
				receipt.PlainSHA = "bad"
			case "uppercase_digest":
				receipt.CipherSHA = strings.Repeat("B", 64)
			case "zero_size":
				receipt.CipherBytes = 0
			case "negative_size":
				receipt.CipherBytes = -1
			case "oversized_archive":
				receipt.CipherBytes = 3 << 20
			}
			payload, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "unknown_field":
				payload = append(payload[:len(payload)-1], []byte(`,"extra":true}`)...)
			case "duplicate_field":
				payload = append(payload[:len(payload)-1], []byte(`,"backup":"backup-1"}`)...)
			case "trailing":
				payload = append(payload, []byte(" {}")...)
			case "malformed":
				payload = []byte("{")
			}
			if _, err := Verify(Envelope{Payload: payload, Signature: ed25519.Sign(private, message(payload))}, public, "fixture", "backup-1"); err == nil {
				t.Fatal("invalid signed profile accepted")
			}
			if !valid(receipt) {
				if _, err := Sign(receipt, private); err == nil {
					t.Fatal("invalid profile signed")
				}
			}
		})
	}
}
