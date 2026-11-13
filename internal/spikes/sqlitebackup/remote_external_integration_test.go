//go:build integration

package sqlitebackup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"private-registry/internal/spikes/backupreceipt"
	"private-registry/internal/spikes/remotebackup"
	"private-registry/internal/spikes/testinfra"
)

type remoteSignedVerifierInput struct {
	Directory     string `json:"directory"`
	Endpoint      string `json:"endpoint"`
	Bucket        string `json:"bucket"`
	ReceiptObject string `json:"receipt_object"`
	Object        string `json:"object"`
	AccessKey     string `json:"access_key"`
	SecretKey     string `json:"secret_key"`
	Identity      string `json:"identity"`
}

type remoteSignedProducerInput struct {
	Directory     string             `json:"directory"`
	Archive       string             `json:"archive"`
	Recipient     string             `json:"recipient"`
	Endpoint      string             `json:"endpoint"`
	Bucket        string             `json:"bucket"`
	Object        string             `json:"object"`
	ReceiptObject string             `json:"receipt_object"`
	AccessKey     string             `json:"access_key"`
	SecretKey     string             `json:"secret_key"`
	SigningKey    ed25519.PrivateKey `json:"signing_key"`
	Installation  string             `json:"installation"`
	Backup        string             `json:"backup"`
}

func (input remoteSignedProducerInput) toProducerInput() producerInput {
	return producerInput{Directory: input.Directory, Archive: input.Archive, Recipient: input.Recipient}
}

type remoteProducerOutput struct {
	PID         int   `json:"producer_pid"`
	CipherBytes int64 `json:"cipher_bytes"`
}

type trustedBackupConfig struct {
	PublicKey    ed25519.PublicKey `json:"public_key"`
	Installation string            `json:"installation"`
	Backup       string            `json:"backup"`
}

func externalVerifyRemoteSigned(ctx context.Context, input remoteSignedVerifierInput) (report externalReport, err error) {
	trustPath := os.Getenv("PRIVATE_REGISTRY_BACKUP_TRUST_CONFIG")
	if trustPath == "" {
		return report, errors.New("trusted recovery configuration unavailable")
	}
	trustFile, err := os.Open(trustPath)
	if err != nil {
		return report, errors.New("trusted recovery configuration unavailable")
	}
	trustInfo, err := trustFile.Stat()
	if err != nil {
		return report, errors.Join(errors.New("trusted recovery configuration metadata unavailable"), trustFile.Close())
	}
	if !trustInfo.Mode().IsRegular() || trustInfo.Size() <= 0 || trustInfo.Size() > 16<<10 || trustInfo.Mode().Perm()&0o022 != 0 {
		return report, errors.Join(errors.New("trusted recovery configuration permissions or size invalid"), trustFile.Close())
	}
	decoder := json.NewDecoder(io.LimitReader(trustFile, 16<<10))
	decoder.DisallowUnknownFields()
	var trust trustedBackupConfig
	decodeErr := decoder.Decode(&trust)
	var trailing any
	trailingErr := decoder.Decode(&trailing)
	closeErr := trustFile.Close()
	if err := errors.Join(decodeErr, trailingErrOrValue(trailingErr), closeErr); err != nil {
		return report, errors.New("trusted recovery configuration invalid")
	}
	identity, err := age.ParseX25519Identity(input.Identity)
	if err != nil {
		return report, errors.New("invalid recovery identity")
	}
	if input.Directory == "" || input.Bucket == "" || input.ReceiptObject == "" || input.Object == "" || input.AccessKey == "" || input.SecretKey == "" {
		return report, errors.New("remote backup fixture configuration incomplete")
	}
	client, err := remotebackup.NewClient(input.Endpoint, input.AccessKey, input.SecretKey)
	if err != nil {
		return report, err
	}
	envelopeBytes, err := readFixtureObject(ctx, client, input.Bucket, input.ReceiptObject, 8<<10)
	if err != nil {
		return report, errors.New("remote signed receipt unavailable")
	}
	envelope, err := decodeReceiptEnvelope(envelopeBytes)
	if err != nil {
		return report, errors.New("remote signed receipt encoding invalid")
	}
	receipt, err := backupreceipt.Verify(envelope, trust.PublicKey, trust.Installation, trust.Backup)
	if err != nil {
		return report, err
	}
	work, err := os.MkdirTemp(input.Directory, "remote-verifier-")
	if err != nil {
		return report, err
	}
	defer func() {
		err = errors.Join(err, os.RemoveAll(work)) // Remove only this verifier's private staging.
	}()
	object, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(input.Bucket), Key: aws.String(input.Object)})
	if err != nil {
		return report, errors.New("remote backup object unavailable")
	}
	archive := filepath.Join(work, "backup.age")
	file, err := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return report, errors.Join(err, object.Body.Close())
	}
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(object.Body, receipt.CipherBytes+1))
	bodyErr := object.Body.Close()
	syncErr := file.Sync()
	fileErr := file.Close()
	if err := errors.Join(copyErr, bodyErr, syncErr, fileErr); err != nil {
		return report, err
	}
	if count != receipt.CipherBytes || hex.EncodeToString(hash.Sum(nil)) != receipt.CipherSHA {
		return report, errors.New("remote ciphertext size or digest mismatch")
	}
	return externalVerify(ctx, verifierInput{Directory: work, Archive: archive, Identity: identity.String(), Receipt: externalReceipt{
		PlainSHA: receipt.PlainSHA, CipherSHA: receipt.CipherSHA, Size: receipt.CipherBytes,
	}})
}

func externalProduceRemoteSigned(ctx context.Context, input remoteSignedProducerInput) (output remoteProducerOutput, err error) {
	if input.Endpoint == "" || input.Bucket == "" || input.Object == "" || input.ReceiptObject == "" || input.AccessKey == "" || input.SecretKey == "" || len(input.SigningKey) != ed25519.PrivateKeySize {
		return output, errors.New("remote producer fixture configuration incomplete")
	}
	client, err := remotebackup.NewClient(input.Endpoint, input.AccessKey, input.SecretKey)
	if err != nil {
		return output, err
	}
	receipt, err := externalProduce(ctx, input.toProducerInput())
	if err != nil {
		return output, err
	}
	defer func() {
		removeErr := os.Remove(input.Archive)
		if !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	signed, err := backupreceipt.Sign(backupreceipt.Receipt{Version: 1, Installation: input.Installation, Backup: input.Backup,
		PlainSHA: receipt.PlainSHA, CipherSHA: receipt.CipherSHA, CipherBytes: receipt.Size}, input.SigningKey)
	if err != nil {
		return output, err
	}
	file, err := os.Open(input.Archive)
	if err != nil {
		return output, err
	}
	info, err := file.Stat()
	if err != nil {
		return output, errors.Join(err, file.Close())
	}
	_, uploadErr := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(input.Bucket), Key: aws.String(input.Object),
		Body: file, ContentLength: aws.Int64(info.Size()), ContentType: aws.String("application/octet-stream"), IfNoneMatch: aws.String("*")})
	if err := errors.Join(uploadErr, file.Close()); err != nil {
		return output, errors.New("remote ciphertext upload failed")
	}
	receiptBytes, err := json.Marshal(signed)
	if err != nil {
		return output, err
	}
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(input.Bucket), Key: aws.String(input.ReceiptObject),
		Body: bytes.NewReader(receiptBytes), ContentLength: aws.Int64(int64(len(receiptBytes))), ContentType: aws.String("application/json"), IfNoneMatch: aws.String("*")}); err != nil {
		return output, errors.New("remote signed receipt upload failed")
	}
	return remoteProducerOutput{PID: receipt.PID, CipherBytes: receipt.Size}, nil
}

func readFixtureObject(ctx context.Context, client *s3.Client, bucket, key string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("positive fixture object limit required")
	}
	object, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(object.Body, maxBytes+1))
	closeErr := object.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("fixture object exceeds byte limit")
	}
	return data, nil
}

func decodeReceiptEnvelope(data []byte) (backupreceipt.Envelope, error) {
	var envelope backupreceipt.Envelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return backupreceipt.Envelope{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return backupreceipt.Envelope{}, errors.New("trailing receipt envelope data")
		}
		return backupreceipt.Envelope{}, err
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, data) {
		return backupreceipt.Envelope{}, errors.New("non-canonical receipt envelope")
	}
	return envelope, nil
}

func trailingErrOrValue(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("trailing trusted recovery configuration")
	}
	return err
}

func TestExternalRemoteVerifierFetchesAndAuthenticatesFlociBackup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	fixture, err := testinfra.StartFloci(ctx)
	if err != nil {
		t.Fatal("start owned Floci (run make setup-floci):", err)
	}
	t.Cleanup(func() {
		if err := fixture.Stop(); err != nil {
			t.Errorf("cleanup owned Floci: %v", err)
		}
	})
	client, err := remotebackup.NewClient(fixture.Endpoint, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	readyClient := &http.Client{Timeout: 250 * time.Millisecond}
	ready, readyCancel := context.WithTimeout(ctx, 30*time.Second)
	defer readyCancel()
	for {
		request, err := http.NewRequestWithContext(ready, http.MethodGet, fixture.Endpoint+"/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, requestErr := readyClient.Do(request)
		if requestErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-ready.Done():
			t.Fatal("owned Floci did not become ready")
		case <-time.After(50 * time.Millisecond):
		}
	}
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	bucket := "external-" + hex.EncodeToString(suffix[:])
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	producerRoot := t.TempDir()
	archive := filepath.Join(producerRoot, "backup.age")
	objectKey := "backups/backup-remote-1.age"
	receiptKey := "backups/backup-remote-1.receipt.json"
	producerInput := remoteSignedProducerInput{
		Directory: producerRoot, Archive: archive, Recipient: identity.Recipient().String(),
		Endpoint: fixture.Endpoint, Bucket: bucket, Object: objectKey, ReceiptObject: receiptKey, AccessKey: "test", SecretKey: "test",
		SigningKey: signingKey, Installation: "fixture", Backup: "backup-remote-1",
	}
	producerOutput, err := runRemoteVerifierWorker(t, ctx, "producer_remote_signed", producerInput, "")
	if err != nil {
		t.Fatal("signed backup producer failed:", err)
	}
	var produced remoteProducerOutput
	if err := json.Unmarshal(producerOutput, &produced); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(producerRoot); err != nil || len(entries) != 0 {
		t.Fatal("remote producer retained local snapshot/ciphertext")
	}
	if produced.CipherBytes <= 0 || produced.CipherBytes > 2<<20 {
		t.Fatal("remote producer receipt has invalid ciphertext size")
	}
	archiveBytes, err := readFixtureObject(ctx, client, bucket, objectKey, 2<<20)
	if err != nil {
		t.Fatal("read only the stored remote ciphertext for the test controller:", err)
	}
	receiptBytes, err := readFixtureObject(ctx, client, bucket, receiptKey, 8<<10)
	if err != nil {
		t.Fatal("read stored signed receipt for the test controller:", err)
	}
	envelope, err := decodeReceiptEnvelope(receiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	backupReceipt, err := backupreceipt.Verify(envelope, publicKey, "fixture", "backup-remote-1")
	if err != nil || backupReceipt.CipherBytes != produced.CipherBytes || int64(len(archiveBytes)) != backupReceipt.CipherBytes {
		t.Fatal("remote receipt and ciphertext disagree", err)
	}

	verifierRoot := t.TempDir()
	staging := filepath.Join(verifierRoot, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	input := remoteSignedVerifierInput{Directory: staging, Endpoint: fixture.Endpoint, Bucket: bucket, ReceiptObject: receiptKey, Object: objectKey,
		AccessKey: "test", SecretKey: "test", Identity: identity.String()}
	trust := trustedBackupConfig{PublicKey: publicKey, Installation: "fixture", Backup: "backup-remote-1"}
	trustPath := writeTrustedBackupConfig(t, verifierRoot, trust)
	output, err := runRemoteVerifierWorker(t, ctx, "verifier_remote_signed", input, trustPath)
	if err != nil {
		t.Fatal("separate remote verifier failed:", err)
	}
	var report externalReport
	if err := json.Unmarshal(output, &report); err != nil || !report.Verified || report.Rows != 128 || report.PID == produced.PID || report.PID == os.Getpid() {
		t.Fatal("remote signed verification report invalid")
	}
	if entries, err := os.ReadDir(staging); err != nil || len(entries) != 0 {
		t.Fatal("remote verifier left ciphertext or plaintext staging")
	}
	if bytes.Contains(archiveBytes, []byte("SQLite format 3\x00")) || !bytes.HasPrefix(archiveBytes, []byte("age-encryption.org/v1")) {
		t.Fatal("uploaded object was not an age-encrypted SQLite snapshot")
	}

	for _, scenario := range []string{"tampered_receipt", "unsigned", "malformed_receipt", "oversized_receipt", "untrusted_key", "another_backup", "another_installation", "cipher_digest", "tampered_ciphertext", "truncated_ciphertext", "oversized_object", "missing_object", "missing_receipt"} {
		t.Run(scenario, func(t *testing.T) {
			attempt := input
			attempt.Object = objectKey
			attemptTrust := trust
			attempt.ReceiptObject = receiptKey
			attemptEnvelope := cloneEnvelope(envelope)
			attemptReceipt := backupReceipt
			switch scenario {
			case "tampered_receipt":
				attemptEnvelope.Payload[len(attemptEnvelope.Payload)-2] ^= 1
				attempt.ReceiptObject = putRemoteMutation(t, ctx, client, bucket, scenario+".json", mustMarshalEnvelope(t, attemptEnvelope))
			case "unsigned":
				attemptEnvelope.Signature = nil
				attempt.ReceiptObject = putRemoteMutation(t, ctx, client, bucket, scenario+".json", mustMarshalEnvelope(t, attemptEnvelope))
			case "malformed_receipt":
				attempt.ReceiptObject = putRemoteMutation(t, ctx, client, bucket, scenario+".json", []byte(`{"payload":"not-base64","signature":[],"unexpected":true}`))
			case "oversized_receipt":
				attempt.ReceiptObject = putRemoteMutation(t, ctx, client, bucket, scenario+".json", bytes.Repeat([]byte("x"), (8<<10)+1))
			case "untrusted_key":
				other, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				attemptTrust.PublicKey = other
			case "another_backup":
				attemptTrust.Backup = "backup-remote-2"
			case "another_installation":
				attemptTrust.Installation = "other"
			case "cipher_digest":
				data := bytes.Clone(archiveBytes)
				data[len(data)-1] ^= 1
				attempt.Object = putRemoteMutation(t, ctx, client, bucket, "digest-mismatch.age", data)
			case "tampered_ciphertext", "truncated_ciphertext":
				data := bytes.Clone(archiveBytes)
				if scenario == "tampered_ciphertext" {
					data[len(data)-1] ^= 1
				} else {
					data = data[:len(data)-1]
				}
				attempt.Object = putRemoteMutation(t, ctx, client, bucket, scenario+".age", data)
				mutatedHash := sha256.Sum256(data)
				attemptReceipt.CipherSHA = hex.EncodeToString(mutatedHash[:])
				attemptReceipt.CipherBytes = int64(len(data))
				attemptEnvelope, err = backupreceipt.Sign(attemptReceipt, signingKey)
				if err != nil {
					t.Fatal(err)
				}
				attempt.ReceiptObject = putRemoteMutation(t, ctx, client, bucket, scenario+".json", mustMarshalEnvelope(t, attemptEnvelope))
			case "oversized_object":
				attempt.Object = putRemoteMutation(t, ctx, client, bucket, "oversized.age", append(bytes.Clone(archiveBytes), 0))
			case "missing_object":
				attempt.Object = "backups/absent.age"
			case "missing_receipt":
				attempt.ReceiptObject = "backups/absent.receipt.json"
			}
			attemptTrustPath := writeTrustedBackupConfig(t, t.TempDir(), attemptTrust)
			attempt.Directory = t.TempDir()
			if err := os.Chmod(attempt.Directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if output, err := runRemoteVerifierWorker(t, ctx, "verifier_remote_signed", attempt, attemptTrustPath); err == nil || len(output) != 0 {
				t.Fatal("invalid remote backup produced a verified report")
			}
			if entries, err := os.ReadDir(attempt.Directory); err != nil || len(entries) != 0 {
				t.Fatal("failed remote verification retained private staging")
			}
		})
	}
	t.Logf("Floci GET → external age/SQLite verifier: producer pid=%d, verifier pid=%d, remote object only after producer copy removal", produced.PID, report.PID)
}

func runRemoteVerifierWorker(t *testing.T, ctx context.Context, mode string, input any, trustPath string) ([]byte, error) {
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
	if trustPath != "" {
		command.Env = append(command.Env, "PRIVATE_REGISTRY_BACKUP_TRUST_CONFIG="+trustPath)
	}
	command.Stdin = bytes.NewReader(data)
	command.WaitDelay = 2 * time.Second
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	output, err := command.Output()
	if bytes.Contains(output, []byte("AGE-SECRET-KEY-")) || bytes.Contains(diagnostics.Bytes(), []byte("AGE-SECRET-KEY-")) {
		t.Fatal("recovery key leaked from external worker")
	}
	return output, err
}

func writeTrustedBackupConfig(t *testing.T, directory string, trust trustedBackupConfig) string {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "trusted-backup.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		t.Fatal(err)
	}
	encodeErr := json.NewEncoder(file).Encode(trust)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(encodeErr, syncErr, closeErr); err != nil {
		t.Fatal(err)
	}
	return path
}

func putRemoteMutation(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, data []byte) string {
	t.Helper()
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(data), ContentLength: aws.Int64(int64(len(data)))}); err != nil {
		t.Fatal(err)
	}
	return key
}

func mustMarshalEnvelope(t *testing.T, envelope backupreceipt.Envelope) []byte {
	t.Helper()
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cloneEnvelope(envelope backupreceipt.Envelope) backupreceipt.Envelope {
	return backupreceipt.Envelope{Payload: bytes.Clone(envelope.Payload), Signature: bytes.Clone(envelope.Signature)}
}
