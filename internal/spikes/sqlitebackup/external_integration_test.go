//go:build integration

package sqlitebackup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"private-registry/internal/spikes/backupreceipt"
)

type externalReceipt struct {
	PlainSHA  string `json:"plain_sha256"`
	CipherSHA string `json:"cipher_sha256"`
	Size      int64  `json:"cipher_bytes"`
	PID       int    `json:"producer_pid"`
}

type producerInput struct {
	Directory string `json:"directory"`
	Archive   string `json:"archive"`
	Recipient string `json:"recipient"`
}

type verifierInput struct {
	Directory string          `json:"directory"`
	Archive   string          `json:"archive"`
	Identity  string          `json:"identity"`
	Receipt   externalReceipt `json:"receipt"`
}

type externalReport struct {
	Verified bool   `json:"verified"`
	SHA      string `json:"restored_sha256"`
	Rows     int    `json:"rows"`
	PID      int    `json:"verifier_pid"`
}

type signedProducerInput struct {
	producerInput
	SigningKey   ed25519.PrivateKey `json:"signing_key"`
	Installation string             `json:"installation"`
	Backup       string             `json:"backup"`
}

type signedProducerOutput struct {
	Envelope backupreceipt.Envelope `json:"envelope"`
	PID      int                    `json:"producer_pid"`
}

type signedVerifierInput struct {
	Directory    string                 `json:"directory"`
	Archive      string                 `json:"archive"`
	Identity     string                 `json:"identity"`
	Envelope     backupreceipt.Envelope `json:"envelope"`
	TrustedKey   ed25519.PublicKey      `json:"trusted_key"`
	Installation string                 `json:"installation"`
	Backup       string                 `json:"backup"`
}

func externalProduce(ctx context.Context, input producerInput) (receipt externalReceipt, err error) {
	recipient, err := age.ParseX25519Recipient(input.Recipient)
	if err != nil {
		return receipt, errors.New("invalid recipient")
	}
	work, err := os.MkdirTemp(input.Directory, "producer-")
	if err != nil {
		return receipt, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(work)) }() // Own synthetic files only.
	dsn, err := DSN(filepath.Join(work, "source.db"))
	if err != nil {
		return receipt, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return receipt, err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	if _, err := db.ExecContext(ctx, `CREATE TABLE owners(id integer PRIMARY KEY); INSERT INTO owners VALUES(1);
		CREATE TABLE entries(id integer PRIMARY KEY, owner_id integer REFERENCES owners(id), payload blob NOT NULL);
		WITH RECURSIVE n(id) AS(SELECT 1 UNION ALL SELECT id+1 FROM n WHERE id<128)
		INSERT INTO entries SELECT id,1,zeroblob(2048) FROM n;`); err != nil {
		return receipt, err
	}
	snapshot := filepath.Join(work, "snapshot.db")
	if _, err := Snapshot(ctx, db, snapshot, Options{PagesPerStep: 8}); err != nil {
		return receipt, err
	}
	if receipt.PlainSHA, err = Digest(snapshot); err != nil {
		return receipt, err
	}
	if err := Encrypt(ctx, snapshot, input.Archive, recipient); err != nil {
		return receipt, err
	}
	if receipt.CipherSHA, err = Digest(input.Archive); err != nil {
		return receipt, err
	}
	info, err := os.Stat(input.Archive)
	if err != nil {
		return receipt, err
	}
	receipt.Size, receipt.PID = info.Size(), os.Getpid()
	return receipt, nil
}

func externalVerify(ctx context.Context, input verifierInput) (report externalReport, err error) {
	identity, err := age.ParseX25519Identity(input.Identity)
	if err != nil {
		return report, errors.New("invalid recovery identity")
	}
	info, err := os.Stat(input.Archive)
	if err != nil {
		return report, err
	}
	if !info.Mode().IsRegular() || info.Size() != input.Receipt.Size || info.Size() > 2<<20 || info.Size() <= 0 {
		return report, errors.New("archive size outside fixture budget")
	}
	hash, err := Digest(input.Archive)
	if err != nil || hash != input.Receipt.CipherSHA {
		return report, errors.New("ciphertext digest mismatch")
	}
	work, err := os.MkdirTemp(input.Directory, "verifier-")
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(work)) }() // Own staging only.
	restored := filepath.Join(work, "restored.db")
	// Authenticate every age chunk before SQLite opens any plaintext.
	if err := Decrypt(ctx, input.Archive, restored, identity); err != nil {
		return report, err
	}
	if report.SHA, err = Digest(restored); err != nil || report.SHA != input.Receipt.PlainSHA {
		return report, errors.New("plaintext digest mismatch")
	}
	uri := &url.URL{Scheme: "file", Path: restored, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	var integrity string
	if err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return report, errors.New("SQLite integrity failed")
	}
	violations, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return report, err
	}
	hasViolation := violations.Next()
	if err := errors.Join(violations.Err(), violations.Close()); err != nil || hasViolation {
		return report, errors.New("SQLite foreign keys failed")
	}
	var payloadBytes int
	if err := db.QueryRowContext(ctx, "SELECT count(*),sum(length(payload)) FROM entries").Scan(&report.Rows, &payloadBytes); err != nil || report.Rows != 128 || payloadBytes != 128*2048 {
		return report, errors.New("restored fixture payload differs")
	}
	report.PID, report.Verified = os.Getpid(), true
	return report, nil
}

func TestExternalBackupProcessHelper(t *testing.T) {
	mode := os.Getenv("PRIVATE_REGISTRY_EXTERNAL_HELPER")
	if mode == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 16<<10))
	decoder.DisallowUnknownFields()
	var result any
	var err error
	switch mode {
	case "producer":
		var input producerInput
		err = decoder.Decode(&input)
		if err == nil {
			result, err = externalProduce(ctx, input)
		}
	case "verifier":
		var input verifierInput
		err = decoder.Decode(&input)
		if err == nil {
			result, err = externalVerify(ctx, input)
		}
	case "producer_signed":
		var input signedProducerInput
		err = decoder.Decode(&input)
		if err == nil {
			var receipt externalReceipt
			receipt, err = externalProduce(ctx, input.producerInput)
			if err == nil {
				var envelope backupreceipt.Envelope
				envelope, err = backupreceipt.Sign(backupreceipt.Receipt{Version: 1, Installation: input.Installation, Backup: input.Backup,
					PlainSHA: receipt.PlainSHA, CipherSHA: receipt.CipherSHA, CipherBytes: receipt.Size}, input.SigningKey)
				result = signedProducerOutput{Envelope: envelope, PID: receipt.PID}
			}
		}
	case "verifier_signed":
		var input signedVerifierInput
		err = decoder.Decode(&input)
		if err == nil {
			var receipt backupreceipt.Receipt
			receipt, err = backupreceipt.Verify(input.Envelope, input.TrustedKey, input.Installation, input.Backup)
			if err == nil {
				result, err = externalVerify(ctx, verifierInput{Directory: input.Directory, Archive: input.Archive, Identity: input.Identity,
					Receipt: externalReceipt{PlainSHA: receipt.PlainSHA, CipherSHA: receipt.CipherSHA, Size: receipt.CipherBytes}})
			}
		}
	default:
		err = errors.New("unknown fixture process")
	}
	if err != nil {
		// Never echo the private input, key, or untrusted tool diagnostics.
		_, _ = fmt.Fprintln(os.Stderr, "external backup fixture failed")
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(1)
	}
	os.Exit(0) // Functions completed deferred cleanup; omit test-harness PASS text.
}

func TestExternalVerifierAuthenticatesProducerReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	producerRoot, verifierRoot := t.TempDir(), t.TempDir()
	archive := filepath.Join(producerRoot, "backup.age")
	worker := func(mode string, input any) ([]byte, error) {
		t.Helper()
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, executable, "-test.run=^TestExternalBackupProcessHelper$")
		command.Env = []string{"PRIVATE_REGISTRY_EXTERNAL_HELPER=" + mode, "GOMAXPROCS=2", "GOMEMLIMIT=256MiB"}
		command.Dir = verifierRoot
		command.WaitDelay = 2 * time.Second
		command.Stdin = bytes.NewReader(data)
		var diagnostics bytes.Buffer
		command.Stderr = &diagnostics
		output, err := command.Output()
		if bytes.Contains(output, []byte(identity.String())) || strings.Contains(diagnostics.String(), identity.String()) {
			t.Fatal("signed receipt worker leaked recovery key")
		}
		return output, err
	}
	output, err := worker("producer_signed", signedProducerInput{producerInput: producerInput{Directory: producerRoot, Archive: archive, Recipient: identity.Recipient().String()},
		SigningKey: private, Installation: "fixture", Backup: "backup-1"})
	if err != nil {
		t.Fatal("signed producer process failed:", err)
	}
	var produced signedProducerOutput
	if err := json.Unmarshal(output, &produced); err != nil {
		t.Fatal(err)
	}
	input := signedVerifierInput{Directory: verifierRoot, Archive: archive, Identity: identity.String(), Envelope: produced.Envelope,
		TrustedKey: public, Installation: "fixture", Backup: "backup-1"}
	output, err = worker("verifier_signed", input)
	if err != nil {
		t.Fatal("authenticated verifier failed:", err)
	}
	var report externalReport
	if err := json.Unmarshal(output, &report); err != nil || !report.Verified || report.Rows != 128 || report.PID == produced.PID || report.PID == os.Getpid() {
		t.Fatal("authenticated external report invalid")
	}
	for _, scenario := range []string{"tampered_receipt", "unsigned", "untrusted_key", "replayed_backup", "another_installation"} {
		t.Run(scenario, func(t *testing.T) {
			attempt := input
			switch scenario {
			case "tampered_receipt":
				attempt.Envelope.Payload = append([]byte(nil), produced.Envelope.Payload...)
				attempt.Envelope.Payload[len(attempt.Envelope.Payload)-2] ^= 1
			case "unsigned":
				attempt.Envelope.Signature = nil
			case "untrusted_key":
				other, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				attempt.TrustedKey = other
			case "replayed_backup":
				attempt.Backup = "backup-2"
			case "another_installation":
				attempt.Installation = "other"
			}
			// Keep the valid archive/key: bypassing receipt authentication would
			// otherwise restore successfully and must make this test fail.
			if output, err := worker("verifier_signed", attempt); err == nil || len(output) != 0 {
				t.Fatal("untrusted/replayed receipt produced a verified report")
			}
		})
	}
	if entries, err := os.ReadDir(verifierRoot); err != nil || len(entries) != 0 {
		t.Fatal("signed verifier left plaintext staging")
	}
	t.Logf("producer pid=%d signed receipt; independent verifier pid=%d trusted pinned key/context before restoring 128 rows", produced.PID, report.PID)
}

func TestExternalSQLiteVerifierWithoutOriginOrProducerPrivateKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	producerRoot, verifierRoot := t.TempDir(), t.TempDir()
	archive := filepath.Join(producerRoot, "backup.age")
	worker := func(mode string, input any) ([]byte, error) {
		t.Helper()
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, executable, "-test.run=^TestExternalBackupProcessHelper$")
		command.WaitDelay = 2 * time.Second
		command.Dir = verifierRoot
		command.Env = []string{"PRIVATE_REGISTRY_EXTERNAL_HELPER=" + mode, "GOMAXPROCS=2", "GOMEMLIMIT=256MiB"}
		command.Stdin = bytes.NewReader(data)
		var diagnostics bytes.Buffer
		command.Stderr = &diagnostics
		output, err := command.Output()
		if strings.Contains(diagnostics.String(), identity.String()) || bytes.Contains(output, []byte(identity.String())) {
			t.Fatal("child process leaked recovery key")
		}
		return output, err
	}
	output, err := worker("producer", producerInput{Directory: producerRoot, Archive: archive, Recipient: identity.Recipient().String()})
	if err != nil {
		t.Fatal("producer process failed:", err)
	}
	var receipt externalReceipt
	if err := json.Unmarshal(output, &receipt); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(producerRoot)
	if err != nil || len(entries) != 1 || entries[0].Name() != "backup.age" {
		t.Fatal("source or plaintext snapshot still present")
	}
	input := verifierInput{Directory: verifierRoot, Archive: archive, Identity: identity.String(), Receipt: receipt}
	output, err = worker("verifier", input)
	if err != nil {
		t.Fatal("independent verifier process failed:", err)
	}
	var report externalReport
	if err := json.Unmarshal(output, &report); err != nil || !report.Verified || report.Rows != 128 || report.SHA != receipt.PlainSHA || report.PID == receipt.PID || report.PID == os.Getpid() || receipt.PID == os.Getpid() {
		t.Fatal("separate-process verification evidence invalid")
	}
	original, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"wrong_key", "tamper", "truncated", "plain_digest", "cipher_digest", "limit", "missing", "not_sqlite", "invalid_foreign_key"} {
		t.Run(scenario, func(t *testing.T) {
			attempt := input
			switch scenario {
			case "wrong_key":
				wrong, err := age.GenerateX25519Identity()
				if err != nil {
					t.Fatal(err)
				}
				attempt.Identity = wrong.String()
			case "tamper", "truncated":
				data := append([]byte(nil), original...)
				if scenario == "tamper" {
					data[len(data)-1] ^= 1
				} else {
					data = data[:len(data)-1]
				}
				attempt.Archive = filepath.Join(producerRoot, scenario+".age")
				if err := os.WriteFile(attempt.Archive, data, 0o600); err != nil {
					t.Fatal(err)
				}
				attempt.Receipt.Size = int64(len(data))
				attempt.Receipt.CipherSHA, err = Digest(attempt.Archive) // Reach age authentication, not just digest mismatch.
				if err != nil {
					t.Fatal(err)
				}
			case "plain_digest":
				attempt.Receipt.PlainSHA = strings.Repeat("0", 64)
			case "cipher_digest":
				attempt.Receipt.CipherSHA = strings.Repeat("0", 64)
			case "limit":
				attempt.Archive = filepath.Join(producerRoot, "oversized.age")
				if err := os.WriteFile(attempt.Archive, make([]byte, 3<<20), 0o600); err != nil {
					t.Fatal(err)
				}
				attempt.Receipt.Size = 3 << 20
				attempt.Receipt.CipherSHA, err = Digest(attempt.Archive)
				if err != nil {
					t.Fatal(err)
				}
			case "missing":
				attempt.Archive = filepath.Join(producerRoot, "absent.age")
			case "not_sqlite", "invalid_foreign_key":
				work := t.TempDir()
				plain := filepath.Join(work, "input.db")
				if scenario == "not_sqlite" {
					if err := os.WriteFile(plain, []byte("not a database"), 0o600); err != nil {
						t.Fatal(err)
					}
				} else {
					uri := &url.URL{Scheme: "file", Path: plain}
					db, err := sql.Open("sqlite", uri.String())
					if err != nil {
						t.Fatal(err)
					}
					_, seedErr := db.Exec(`PRAGMA foreign_keys=OFF;
						CREATE TABLE owners(id integer PRIMARY KEY); INSERT INTO owners VALUES(1);
						CREATE TABLE entries(id integer PRIMARY KEY,owner_id integer REFERENCES owners(id),payload blob);
						WITH RECURSIVE n(id) AS(SELECT 1 UNION ALL SELECT id+1 FROM n WHERE id<128)
						INSERT INTO entries SELECT id,999,zeroblob(2048) FROM n;`)
					if err := errors.Join(seedErr, db.Close()); err != nil {
						t.Fatal(err)
					}
				}
				attempt.Archive = filepath.Join(work, "invalid.age")
				if err := Encrypt(ctx, plain, attempt.Archive, identity.Recipient()); err != nil {
					t.Fatal(err)
				}
				attempt.Receipt.PlainSHA, err = Digest(plain)
				if err != nil {
					t.Fatal(err)
				}
				attempt.Receipt.CipherSHA, err = Digest(attempt.Archive)
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(attempt.Archive)
				if err != nil {
					t.Fatal(err)
				}
				attempt.Receipt.Size = info.Size() // Valid age/digests; reject actual DB semantics.
			}
			if output, err := worker("verifier", attempt); err == nil || len(output) != 0 {
				t.Fatal("invalid backup reported successful external verification")
			}
		})
	}
	if entries, err := os.ReadDir(verifierRoot); err != nil || len(entries) != 0 {
		t.Fatal("verifier left private plaintext staging")
	}
	t.Logf("producer pid=%d (public recipient only), verifier pid=%d: 128 rows/262144 payload bytes restored without origin, no plaintext staging remains", receipt.PID, report.PID)
}
