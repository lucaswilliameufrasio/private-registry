//go:build integration

package postgresbackup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"private-registry/internal/spikes/remotebackup"
)

type postgresTrustedBackupConfig struct {
	PublicKey    ed25519.PublicKey `json:"public_key"`
	Installation string            `json:"installation"`
	Backup       string            `json:"backup"`
	ToolsMajor   int               `json:"tools_major"`
}

type postgresRemoteProducerInput struct {
	Directory     string             `json:"directory"`
	Archive       string             `json:"archive"`
	Source        string             `json:"source"`
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

type postgresRemoteVerifierInput struct {
	Directory     string `json:"directory"`
	Endpoint      string `json:"endpoint"`
	Bucket        string `json:"bucket"`
	ReceiptObject string `json:"receipt_object"`
	Object        string `json:"object"`
	AccessKey     string `json:"access_key"`
	SecretKey     string `json:"secret_key"`
	Identity      string `json:"identity"`
}

type postgresRemoteProducerReport struct {
	PID         int   `json:"producer_pid"`
	ToolsMajor  int   `json:"tools_major"`
	CipherBytes int64 `json:"ciphertext_bytes"`
}

type postgresRemoteVerifierReport struct {
	Verified    bool `json:"verified"`
	Rows        int  `json:"rows"`
	PayloadSize int  `json:"payload_bytes"`
	ToolsMajor  int  `json:"tools_major"`
	PID         int  `json:"verifier_pid"`
}

func TestExternalPostgresBackupProcessHelper(t *testing.T) {
	mode := os.Getenv("PRIVATE_REGISTRY_PG_EXTERNAL_HELPER")
	if mode == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 32<<10))
	decoder.DisallowUnknownFields()
	var result any
	var err error
	switch mode {
	case "producer":
		var input postgresRemoteProducerInput
		err = decoder.Decode(&input)
		if err == nil {
			result, err = externalPostgresProduce(ctx, input)
		}
	case "verifier":
		var input postgresRemoteVerifierInput
		err = decoder.Decode(&input)
		if err == nil {
			result, err = externalPostgresVerify(ctx, t, input)
		}
	default:
		err = errors.New("unknown PostgreSQL fixture worker")
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "external PostgreSQL backup fixture failed: %v\n", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func externalPostgresProduce(ctx context.Context, input postgresRemoteProducerInput) (output postgresRemoteProducerReport, err error) {
	if !databaseName.MatchString(input.Source) || input.Directory == "" || input.Archive == "" || input.Endpoint == "" ||
		input.Bucket == "" || input.Object == "" || input.ReceiptObject == "" || input.AccessKey == "" || input.SecretKey == "" ||
		len(input.SigningKey) != ed25519.PrivateKeySize {
		return output, errors.New("PostgreSQL producer fixture configuration invalid")
	}
	client, err := remotebackup.NewClient(input.Endpoint, input.AccessKey, input.SecretKey)
	if err != nil {
		return output, err
	}
	identity, err := age.ParseX25519Recipient(input.Recipient)
	if err != nil {
		return output, errors.New("invalid public recovery recipient")
	}
	dump, err := Dump(ctx, fixtureTools, input.Source, "", input.Archive, identity, maxRemotePlaintextBytes)
	if err != nil {
		return output, err
	}
	defer func() {
		removeErr := os.Remove(input.Archive)
		if !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	cipherDigest, cipherBytes, err := digestRegularFile(input.Archive, maxRemoteCiphertextBytes)
	if err != nil {
		return output, err
	}
	receipt := RemoteBackupReceipt{Version: 1, Engine: "postgresql", ToolsMajor: dump.ToolsMajor,
		Installation: input.Installation, Backup: input.Backup, PlaintextSHA: dump.PlaintextSHA256,
		PlaintextSize: dump.PlaintextBytes, CiphertextSHA: cipherDigest, CiphertextSize: cipherBytes}
	envelope, err := SignRemoteBackupReceipt(receipt, input.SigningKey)
	if err != nil {
		return output, err
	}
	archive, err := os.Open(input.Archive)
	if err != nil {
		return output, err
	}
	_, uploadErr := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(input.Bucket), Key: aws.String(input.Object),
		Body: archive, ContentLength: aws.Int64(cipherBytes), ContentType: aws.String("application/octet-stream"), IfNoneMatch: aws.String("*")})
	if err := errors.Join(uploadErr, archive.Close()); err != nil {
		return output, errors.New("PostgreSQL ciphertext upload failed")
	}
	receiptBytes, err := json.Marshal(envelope)
	if err != nil {
		return output, err
	}
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(input.Bucket), Key: aws.String(input.ReceiptObject),
		Body: bytes.NewReader(receiptBytes), ContentLength: aws.Int64(int64(len(receiptBytes))), ContentType: aws.String("application/json"), IfNoneMatch: aws.String("*")}); err != nil {
		return output, errors.New("PostgreSQL signed receipt upload failed")
	}
	return postgresRemoteProducerReport{PID: os.Getpid(), ToolsMajor: dump.ToolsMajor, CipherBytes: cipherBytes}, nil
}

func externalPostgresVerify(ctx context.Context, t *testing.T, input postgresRemoteVerifierInput) (report postgresRemoteVerifierReport, err error) {
	t.Helper()
	trust, err := readPostgresTrustedConfig(os.Getenv("PRIVATE_REGISTRY_PG_BACKUP_TRUST_CONFIG"))
	if err != nil {
		return report, err
	}
	if trust.ToolsMajor != fixtureTools.ExpectedMajor || input.Directory == "" || input.Bucket == "" || input.ReceiptObject == "" ||
		input.Object == "" || input.AccessKey == "" || input.SecretKey == "" {
		return report, errors.New("PostgreSQL verifier fixture configuration mismatch")
	}
	client, err := remotebackup.NewClient(input.Endpoint, input.AccessKey, input.SecretKey)
	if err != nil {
		return report, err
	}
	envelopeBytes, err := readPostgresFixtureObject(ctx, client, input.Bucket, input.ReceiptObject, 8<<10)
	if err != nil {
		return report, errors.New("PostgreSQL remote receipt unavailable")
	}
	envelope, err := decodePostgresRemoteEnvelope(envelopeBytes)
	if err != nil {
		return report, errors.New("PostgreSQL remote receipt encoding invalid")
	}
	receipt, err := VerifyRemoteBackupReceipt(envelope, trust.PublicKey, trust.Installation, trust.Backup, trust.ToolsMajor)
	if err != nil {
		return report, err
	}
	identity, err := age.ParseX25519Identity(input.Identity)
	if err != nil {
		return report, errors.New("invalid PostgreSQL recovery identity")
	}
	work, err := os.MkdirTemp(input.Directory, "postgres-verifier-")
	if err != nil {
		return report, err
	}
	defer func() {
		err = errors.Join(err, os.RemoveAll(work))
	}()
	archivePath := filepath.Join(work, "remote.age")
	if err := downloadPostgresCiphertext(ctx, client, input.Bucket, input.Object, archivePath, receipt); err != nil {
		return report, err
	}
	target, err := createPostgresDatabase(ctx)
	if err != nil {
		return report, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		err = errors.Join(err, run(fixtureTools.command(cleanup, "dropdb", "--username=postgres", "--no-password", target), io.Discard, nil))
	}()
	if err := Restore(ctx, fixtureTools, target, archivePath, identity, receipt.PlaintextSHA, receipt.PlaintextSize, work); err != nil {
		return report, err
	}
	rows, err := queryPostgres(ctx, target, "SELECT count(*)||':'||sum(octet_length(payload)) FROM packages;")
	if err != nil || rows != "128:262144" {
		return report, errors.New("restored PostgreSQL fixture rows or payload differ")
	}
	owners, err := queryPostgres(ctx, target, "SELECT count(*) FROM owners WHERE id=1;")
	if err != nil || owners != "1" {
		return report, errors.New("restored PostgreSQL owner reference differs")
	}
	foreignKeys, err := queryPostgres(ctx, target, "SELECT count(*) FROM pg_constraint WHERE contype='f' AND conrelid='packages'::regclass;")
	if err != nil || foreignKeys != "1" {
		return report, errors.New("restored PostgreSQL foreign key missing")
	}
	matching, err := queryPostgres(ctx, target, "SELECT count(*) FROM packages WHERE owner_id=1 AND payload LIKE 'synthetic-private-metadata-'||id||'-%';")
	if err != nil || matching != "128" {
		return report, errors.New("restored PostgreSQL payload mismatch")
	}
	sequence, err := queryPostgres(ctx, target, "INSERT INTO packages(owner_id,payload) VALUES(1,'sequence-check') RETURNING id;")
	if err != nil || sequence != "129" {
		return report, errors.New("restored PostgreSQL identity sequence mismatch")
	}
	entries, err := os.ReadDir(work)
	if err != nil || len(entries) != 1 || entries[0].Name() != "remote.age" {
		return report, errors.New("PostgreSQL verifier retained plaintext staging")
	}
	return postgresRemoteVerifierReport{Verified: true, Rows: 128, PayloadSize: 128 * 2048, ToolsMajor: receipt.ToolsMajor, PID: os.Getpid()}, nil
}

func readPostgresTrustedConfig(path string) (config postgresTrustedBackupConfig, err error) {
	if path == "" {
		return config, errors.New("PostgreSQL trusted recovery config unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return config, errors.New("PostgreSQL trusted recovery config unavailable")
	}
	info, err := file.Stat()
	if err != nil {
		return config, errors.Join(errors.New("PostgreSQL trusted config metadata unavailable"), file.Close())
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<10 || info.Mode().Perm()&0o022 != 0 {
		return config, errors.Join(errors.New("PostgreSQL trusted config permissions or size invalid"), file.Close())
	}
	decoder := json.NewDecoder(io.LimitReader(file, 16<<10))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&config)
	var trailing any
	trailingErr := decoder.Decode(&trailing)
	closeErr := file.Close()
	if err := errors.Join(decodeErr, postgresTrailingError(trailingErr), closeErr); err != nil {
		return postgresTrustedBackupConfig{}, errors.New("PostgreSQL trusted recovery config invalid")
	}
	return config, nil
}

func postgresTrailingError(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("trailing PostgreSQL trusted config data")
	}
	return err
}

func decodePostgresRemoteEnvelope(data []byte) (RemoteBackupEnvelope, error) {
	var envelope RemoteBackupEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return RemoteBackupEnvelope{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return RemoteBackupEnvelope{}, errors.New("trailing PostgreSQL receipt data")
		}
		return RemoteBackupEnvelope{}, err
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, data) {
		return RemoteBackupEnvelope{}, errors.New("non-canonical PostgreSQL receipt envelope")
	}
	return envelope, nil
}

func readPostgresFixtureObject(ctx context.Context, client *s3.Client, bucket, key string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("positive PostgreSQL fixture object limit required")
	}
	object, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(object.Body, limit+1))
	closeErr := object.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("PostgreSQL fixture object exceeds limit")
	}
	return data, nil
}

func downloadPostgresCiphertext(ctx context.Context, client *s3.Client, bucket, key, destination string, receipt RemoteBackupReceipt) (err error) {
	object, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return errors.New("PostgreSQL remote ciphertext unavailable")
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.Join(err, object.Body.Close())
	}
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(object.Body, receipt.CiphertextSize+1))
	bodyErr := object.Body.Close()
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(copyErr, bodyErr, syncErr, closeErr); err != nil {
		return err
	}
	if count != receipt.CiphertextSize || hex.EncodeToString(hash.Sum(nil)) != receipt.CiphertextSHA {
		return errors.New("PostgreSQL remote ciphertext size or digest mismatch")
	}
	return ctx.Err()
}

func digestRegularFile(path string, limit int64) (digest string, size int64, err error) {
	if limit <= 0 {
		return "", 0, errors.New("positive PostgreSQL ciphertext limit required")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	info, err := file.Stat()
	if err != nil {
		return "", 0, errors.Join(err, file.Close())
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return "", 0, errors.Join(errors.New("PostgreSQL ciphertext file type or size invalid"), file.Close())
	}
	hash := sha256.New()
	count, copyErr := io.Copy(hash, io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return "", 0, err
	}
	if count != info.Size() {
		return "", 0, errors.New("PostgreSQL ciphertext changed while hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), count, nil
}

func createPostgresDatabase(ctx context.Context) (string, error) {
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	name := "spike_external_" + hex.EncodeToString(suffix[:])
	if err := run(fixtureTools.command(ctx, "createdb", "--username=postgres", "--no-password", name), io.Discard, nil); err != nil {
		return "", err
	}
	return name, nil
}

func queryPostgres(ctx context.Context, database, statement string) (string, error) {
	var output bytes.Buffer
	err := run(fixtureTools.command(ctx, "psql", "--username=postgres", "--no-password", "--quiet", "--tuples-only", "--no-align",
		"--set=ON_ERROR_STOP=1", "--dbname="+database), &output, strings.NewReader(statement))
	return strings.TrimSpace(output.String()), err
}

func TestExternalPostgresRemoteRecoveryWithoutOriginOrProducerCiphertext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	store, endpoint := remoteStore(t, ctx)
	source := database(t, ctx)
	serverVersion := query(t, ctx, source, "SHOW server_version;")
	if !strings.HasPrefix(serverVersion, "18.") {
		t.Fatalf("unexpected fixture PostgreSQL version: %s", serverVersion)
	}
	query(t, ctx, source, `CREATE TABLE owners(id integer PRIMARY KEY);
		CREATE TABLE packages(id integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, owner_id integer NOT NULL REFERENCES owners(id), payload text NOT NULL);
		INSERT INTO owners VALUES(1);
		INSERT INTO packages(owner_id,payload) SELECT 1,left(repeat('synthetic-private-metadata-'||n||'-',100),2048) FROM generate_series(1,128) n;`)
	identity := recoveryIdentity(t)
	publicKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	producerDirectory := t.TempDir()
	archivePath := filepath.Join(producerDirectory, "postgres.age")
	objectKey := "backups/postgres-external-1.age"
	receiptKey := "backups/postgres-external-1.receipt.json"
	producerInput := postgresRemoteProducerInput{Directory: producerDirectory, Archive: archivePath, Source: source,
		Recipient: identity.Recipient().String(), Endpoint: endpoint, Bucket: store.Bucket, Object: objectKey, ReceiptObject: receiptKey,
		AccessKey: "test", SecretKey: "test", SigningKey: signingKey, Installation: "fixture", Backup: "postgres-external-1"}
	producerOutput, err := runPostgresExternalWorker(t, ctx, "producer", producerInput, "")
	if err != nil {
		t.Fatal("external PostgreSQL producer failed:", err)
	}
	var producer postgresRemoteProducerReport
	if err := json.Unmarshal(producerOutput, &producer); err != nil || producer.ToolsMajor != 18 || producer.CipherBytes <= 0 || producer.PID == os.Getpid() {
		t.Fatal("external PostgreSQL producer report invalid", err)
	}
	if entries, err := os.ReadDir(producerDirectory); err != nil || len(entries) != 0 {
		t.Fatal("producer retained dump/ciphertext staging")
	}
	if err := run(fixtureTools.command(ctx, "dropdb", "--username=postgres", "--no-password", source), io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if actual := query(t, ctx, "postgres", "SELECT count(*) FROM pg_database WHERE datname='"+source+"';"); actual != "0" {
		t.Fatal("PostgreSQL origin remains available")
	}

	archiveBytes, err := readPostgresFixtureObject(ctx, store.Client, store.Bucket, objectKey, maxRemoteCiphertextBytes)
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := readPostgresFixtureObject(ctx, store.Client, store.Bucket, receiptKey, 8<<10)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := decodePostgresRemoteEnvelope(receiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	remoteReceipt, err := VerifyRemoteBackupReceipt(envelope, publicKey, "fixture", "postgres-external-1", 18)
	if err != nil || remoteReceipt.CiphertextSize != producer.CipherBytes || int64(len(archiveBytes)) != remoteReceipt.CiphertextSize {
		t.Fatal("remote PostgreSQL receipt and ciphertext differ", err)
	}
	if bytes.Contains(archiveBytes, []byte("synthetic-private-metadata")) || !bytes.HasPrefix(archiveBytes, []byte("age-encryption.org/v1")) {
		t.Fatal("remote PostgreSQL object is not age-encrypted")
	}

	verifierRoot := t.TempDir()
	stage := filepath.Join(verifierRoot, "staging")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	input := postgresRemoteVerifierInput{Directory: stage, Endpoint: endpoint, Bucket: store.Bucket, ReceiptObject: receiptKey, Object: objectKey,
		AccessKey: "test", SecretKey: "test", Identity: identity.String()}
	trust := postgresTrustedBackupConfig{PublicKey: publicKey, Installation: "fixture", Backup: "postgres-external-1", ToolsMajor: 18}
	trustPath := writePostgresTrustedConfig(t, t.TempDir(), trust)
	output, err := runPostgresExternalWorker(t, ctx, "verifier", input, trustPath)
	if err != nil {
		t.Fatal("external PostgreSQL verifier failed:", err)
	}
	var report postgresRemoteVerifierReport
	if err := json.Unmarshal(output, &report); err != nil || !report.Verified || report.Rows != 128 || report.PayloadSize != 262144 || report.ToolsMajor != 18 || report.PID == producer.PID || report.PID == os.Getpid() {
		t.Fatal("external PostgreSQL recovery report invalid", err)
	}
	if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
		t.Fatal("external PostgreSQL verifier retained private staging")
	}

	for _, scenario := range []string{"tampered_receipt", "unsigned", "malformed_receipt", "oversized_receipt", "untrusted_key", "another_backup", "another_installation", "wrong_tools_major", "cipher_digest", "tampered_ciphertext", "truncated_ciphertext", "oversized_object", "missing_object", "missing_receipt", "non_archive"} {
		t.Run(scenario, func(t *testing.T) {
			attempt := input
			attemptTrust := trust
			attemptEnvelope := clonePostgresEnvelope(envelope)
			attemptReceipt := remoteReceipt
			switch scenario {
			case "tampered_receipt":
				attemptEnvelope.Payload[len(attemptEnvelope.Payload)-2] ^= 1
				attempt.ReceiptObject = putPostgresFixtureObject(t, ctx, store.Client, store.Bucket, scenario+".json", mustMarshalPostgresEnvelope(t, attemptEnvelope))
			case "unsigned":
				attemptEnvelope.Signature = nil
				attempt.ReceiptObject = putPostgresFixtureObject(t, ctx, store.Client, store.Bucket, scenario+".json", mustMarshalPostgresEnvelope(t, attemptEnvelope))
			case "malformed_receipt":
				attempt.ReceiptObject = putPostgresFixtureObject(t, ctx, store.Client, store.Bucket, scenario+".json", []byte(`{"payload":"invalid","signature":[],"extra":true}`))
			case "oversized_receipt":
				attempt.ReceiptObject = putPostgresFixtureObject(t, ctx, store.Client, store.Bucket, scenario+".json", bytes.Repeat([]byte("x"), (8<<10)+1))
			case "untrusted_key":
				other, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				attemptTrust.PublicKey = other
			case "another_backup":
				attemptTrust.Backup = "another-backup"
			case "another_installation":
				attemptTrust.Installation = "another-installation"
			case "wrong_tools_major":
				attemptTrust.ToolsMajor = 17
			case "cipher_digest":
				data := bytes.Clone(archiveBytes)
				data[len(data)-1] ^= 1
				attempt.Object = putPostgresFixtureObject(t, ctx, store.Client, store.Bucket, "digest-mismatch.age", data)
			case "tampered_ciphertext", "truncated_ciphertext":
				data := bytes.Clone(archiveBytes)
				if scenario == "tampered_ciphertext" {
					data[len(data)-1] ^= 1
				} else {
					data = data[:len(data)-1]
				}
				attempt.Object = putPostgresFixtureObject(t, ctx, store.Client, store.Bucket, scenario+".age", data)
				digest := sha256.Sum256(data)
				attemptReceipt.CiphertextSHA = hex.EncodeToString(digest[:])
				attemptReceipt.CiphertextSize = int64(len(data))
				attemptEnvelope, err = SignRemoteBackupReceipt(attemptReceipt, signingKey)
				if err != nil {
					t.Fatal(err)
				}
				attempt.ReceiptObject = putPostgresFixtureObject(t, ctx, store.Client, store.Bucket, scenario+".json", mustMarshalPostgresEnvelope(t, attemptEnvelope))
			case "oversized_object":
				attempt.Object = putPostgresFixtureObject(t, ctx, store.Client, store.Bucket, scenario+".age", append(bytes.Clone(archiveBytes), 0))
			case "missing_object":
				attempt.Object = "backups/not-found.age"
			case "missing_receipt":
				attempt.ReceiptObject = "backups/not-found.receipt.json"
			case "non_archive":
				plaintext := []byte("not a PostgreSQL custom archive")
				ciphertext := filepath.Join(t.TempDir(), "invalid.age")
				file, err := os.OpenFile(ciphertext, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				sealed, err := age.Encrypt(file, identity.Recipient())
				if err != nil {
					if closeErr := file.Close(); closeErr != nil {
						t.Fatal(errors.Join(err, closeErr))
					}
					t.Fatal(err)
				}
				_, writeErr := sealed.Write(plaintext)
				if err := errors.Join(writeErr, sealed.Close(), file.Close()); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(ciphertext)
				if err != nil {
					t.Fatal(err)
				}
				plainDigest := sha256.Sum256(plaintext)
				cipherDigest := sha256.Sum256(data)
				attempt.Object = putPostgresFixtureObject(t, ctx, store.Client, store.Bucket, "non-archive.age", data)
				attemptReceipt.PlaintextSHA = hex.EncodeToString(plainDigest[:])
				attemptReceipt.PlaintextSize = int64(len(plaintext))
				attemptReceipt.CiphertextSHA = hex.EncodeToString(cipherDigest[:])
				attemptReceipt.CiphertextSize = int64(len(data))
				attemptEnvelope, err = SignRemoteBackupReceipt(attemptReceipt, signingKey)
				if err != nil {
					t.Fatal(err)
				}
				attempt.ReceiptObject = putPostgresFixtureObject(t, ctx, store.Client, store.Bucket, "non-archive.json", mustMarshalPostgresEnvelope(t, attemptEnvelope))
			}
			attemptTrustPath := writePostgresTrustedConfig(t, t.TempDir(), attemptTrust)
			attempt.Directory = t.TempDir()
			if err := os.Chmod(attempt.Directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if output, err := runPostgresExternalWorker(t, ctx, "verifier", attempt, attemptTrustPath); err == nil || len(output) != 0 {
				t.Fatal("invalid PostgreSQL backup produced a verified report")
			}
			if entries, err := os.ReadDir(attempt.Directory); err != nil || len(entries) != 0 {
				t.Fatal("failed PostgreSQL verifier retained staging")
			}
		})
	}
	t.Logf("PostgreSQL → age → Floci → external GET/pg_restore: producer pid=%d, verifier pid=%d; origin and producer archive removed", producer.PID, report.PID)
}

func runPostgresExternalWorker(t *testing.T, ctx context.Context, mode string, input any, trustPath string) ([]byte, error) {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, executable, "-test.run=^TestExternalPostgresBackupProcessHelper$")
	command.Env = []string{
		"PRIVATE_REGISTRY_PG_FIXTURE_CONTAINER=" + fixtureContainerName,
		"PRIVATE_REGISTRY_PG_DOCKER_CONTEXT=" + fixtureDockerContext,
		"PRIVATE_REGISTRY_PG_EXTERNAL_HELPER=" + mode,
		"DOCKER_CONTEXT=" + fixtureDockerContext,
		"PATH=" + os.Getenv("PATH"),
		"GOMAXPROCS=2",
		"GOMEMLIMIT=512MiB",
	}
	if trustPath != "" {
		command.Env = append(command.Env, "PRIVATE_REGISTRY_PG_BACKUP_TRUST_CONFIG="+trustPath)
	}
	command.Stdin = bytes.NewReader(data)
	command.WaitDelay = 2 * time.Second
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	output, err := command.Output()
	if bytes.Contains(output, []byte("AGE-SECRET-KEY-")) || bytes.Contains(diagnostics.Bytes(), []byte("AGE-SECRET-KEY-")) {
		t.Fatal("PostgreSQL helper leaked recovery identity")
	}
	if err != nil {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(diagnostics.String()))
	}
	return output, err
}

func writePostgresTrustedConfig(t *testing.T, directory string, config postgresTrustedBackupConfig) string {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "trusted-postgres-backup.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		t.Fatal(err)
	}
	encodeErr := json.NewEncoder(file).Encode(config)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(encodeErr, syncErr, closeErr); err != nil {
		t.Fatal(err)
	}
	return path
}

func putPostgresFixtureObject(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, data []byte) string {
	t.Helper()
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(data), ContentLength: aws.Int64(int64(len(data)))}); err != nil {
		t.Fatal(err)
	}
	return key
}

func mustMarshalPostgresEnvelope(t *testing.T, envelope RemoteBackupEnvelope) []byte {
	t.Helper()
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func clonePostgresEnvelope(envelope RemoteBackupEnvelope) RemoteBackupEnvelope {
	return RemoteBackupEnvelope{Payload: bytes.Clone(envelope.Payload), Signature: bytes.Clone(envelope.Signature)}
}
