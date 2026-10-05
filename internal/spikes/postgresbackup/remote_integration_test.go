//go:build integration

package postgresbackup

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"private-registry/internal/spikes/remotebackup"
)

const flociImage = "floci/floci:2.1.0@sha256:f5aa8c18302cedb4f2385f5c4e455b3efc77fee6bf7b6e5d1712b2817ba102db"

func remoteStore(t *testing.T, ctx context.Context) remotebackup.Store {
	t.Helper()
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(suffix[:])
	name := "private-registry-pg-floci-" + id
	output, err := exec.CommandContext(ctx, "docker", "run", "--detach", "--pull=never", "--name", name,
		"--user=1001:0", "--cpus=2", "--memory=512m", "--pids-limit=256", "--cap-drop=ALL",
		"--security-opt=no-new-privileges", "--publish", "127.0.0.1::4566",
		"--env", "LOCALSTACK_PARITY=false", "--env", "FLOCI_SERVICES_S3_ENFORCE_AUTH=true", flociImage).CombinedOutput()
	if err != nil {
		t.Fatalf("start owned Floci (run make setup-floci): %v %s", err, output)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if output, err := exec.CommandContext(cleanup, "docker", "rm", "--force", "--volumes", name).CombinedOutput(); err != nil {
			t.Errorf("cleanup owned Floci: %v %s", err, output)
		}
	})
	port, err := exec.CommandContext(ctx, "docker", "port", name, "4566/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + strings.TrimSpace(string(port))
	ready, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	httpClient := &http.Client{Timeout: 200 * time.Millisecond}
	for {
		request, err := http.NewRequestWithContext(ready, http.MethodGet, endpoint+"/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := httpClient.Do(request)
		if err == nil {
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
	client, err := remotebackup.NewClient(endpoint, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	bucket := "postgres-" + id
	if _, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	return remotebackup.Store{Client: client, Bucket: bucket}
}

// fetchArchive is an experiment-only download boundary: no overwrite, bounded
// ciphertext and independent digest. It does not authenticate a manifest.
func fetchArchive(ctx context.Context, store remotebackup.Store, key, destination, digest string, limit int64) (err error) {
	if limit <= 0 || limit > 32<<20 {
		return errors.New("fixture ciphertext limit must be in (0, 32 MiB]")
	}
	object, err := store.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(store.Bucket), Key: aws.String(key)})
	if err != nil {
		return err
	}
	var file *os.File
	defer func() {
		err = errors.Join(err, object.Body.Close())
		if file != nil {
			err = errors.Join(err, file.Close())
			if err != nil {
				err = errors.Join(err, os.Remove(destination))
			}
		}
	}()
	file, err = os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(object.Body, limit+1))
	if err != nil {
		return err
	}
	if count > limit || hex.EncodeToString(hash.Sum(nil)) != digest {
		return errors.New("remote ciphertext limit or SHA-256 mismatch")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return file.Sync()
}

func TestPostgresRemoteRecoveryWithoutOriginOrLocalArchive(t *testing.T) {
	// More time than an individual local operation, bounded on shared machines.
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	store := remoteStore(t, ctx)
	source := database(t, ctx)
	query(t, ctx, source, `CREATE TABLE owners(id integer PRIMARY KEY);
		CREATE TABLE packages(id integer PRIMARY KEY, owner_id integer NOT NULL REFERENCES owners(id), payload text NOT NULL);
		INSERT INTO owners VALUES(1);
		INSERT INTO packages SELECT n,1,'synthetic-private-metadata-'||n FROM generate_series(1,128) n;`)
	identity := recoveryIdentity(t)
	local := t.TempDir()
	ciphertext := filepath.Join(local, "postgres.age")
	receipt, err := Dump(ctx, fixtureTools, source, "", ciphertext, identity.Recipient(), 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	cipherDigest := hex.EncodeToString(hash.Sum(nil))
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	// Already age-encrypted: send the file directly, never wrap it in age again.
	_, putErr := store.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(store.Bucket), Key: aws.String("postgres.age"), Body: file,
		ContentLength: aws.Int64(info.Size()), IfNoneMatch: aws.String("*"), ContentType: aws.String("application/octet-stream"),
	})
	if err := errors.Join(putErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	if err := run(fixtureTools.command(ctx, "dropdb", "--username=postgres", "--no-password", source), io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ciphertext); err != nil {
		t.Fatal(err)
	}
	assertNoStage(t, local)
	if actual := query(t, ctx, "postgres", "SELECT count(*) FROM pg_database WHERE datname='"+source+"';"); actual != "0" {
		t.Fatal("source database remains available")
	}
	// The only archive copy available now is the object in Floci. No plaintext
	// or ciphertext byte slice has been retained from the original file.
	recovered := filepath.Join(t.TempDir(), "remote.age")
	if err := fetchArchive(ctx, store, "postgres.age", recovered, cipherDigest, info.Size()); err != nil {
		t.Fatal(err)
	}
	target := database(t, ctx)
	stage := t.TempDir()
	if err := Restore(ctx, fixtureTools, target, recovered, identity, receipt.PlaintextSHA256, receipt.PlaintextBytes, stage); err != nil {
		t.Fatal(err)
	}
	assertNoStage(t, stage)
	if actual := query(t, ctx, target, "SELECT count(*) FROM packages WHERE owner_id=1 AND payload='synthetic-private-metadata-'||id;"); actual != "128" {
		t.Fatalf("remote recovery payload/reference mismatch: %s", actual)
	}
	if actual := query(t, ctx, target, "SELECT count(*) FROM packages;"); actual != "128" {
		t.Fatal("remote recovery contains unexpected rows")
	}
	if actual := query(t, ctx, target, "SELECT count(*) FROM pg_constraint WHERE conrelid='packages'::regclass AND contype='f';"); actual != "1" {
		t.Fatal("remote recovery foreign key absent")
	}
	t.Logf("PostgreSQL → age → S3/Floci → new database: %d archive bytes / %d ciphertext bytes; origin/local archive absent; 128 rows restored", receipt.PlaintextBytes, info.Size())

	// Mutations are derived from the freshly downloaded remote object, after
	// the success proof. Each failure uses a new, empty recovery database.
	remoteBytes, err := os.ReadFile(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(remoteBytes, []byte("synthetic-private-metadata")) {
		t.Fatal("plaintext metadata exposed in remote archive")
	}
	for _, kind := range []string{"tamper", "truncated", "wrong_key", "missing", "size", "digest", "existing", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			key, digest, limit := "postgres.age", cipherDigest, info.Size()
			op, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			target := database(t, ctx)
			output := filepath.Join(t.TempDir(), "remote.age")
			if kind == "tamper" || kind == "truncated" {
				data := bytes.Clone(remoteBytes)
				if kind == "tamper" {
					data[len(data)-1] ^= 1
				} else {
					data = data[:len(data)-16]
				}
				key = kind + ".age"
				if _, err := store.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(store.Bucket), Key: aws.String(key), Body: bytes.NewReader(data)}); err != nil {
					t.Fatal(err)
				}
				// Even if a digest were replaced alongside the damaged object,
				// age authentication must prevent any database mutation.
				hash := sha256.Sum256(data)
				digest = hex.EncodeToString(hash[:])
			} else if kind == "missing" {
				key = "missing.age"
			} else if kind == "size" {
				limit--
			} else if kind == "digest" {
				digest = strings.Repeat("0", 64)
			} else if kind == "existing" {
				if err := os.WriteFile(output, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if kind == "canceled" {
				cancel()
			}
			err := fetchArchive(op, store, key, output, digest, limit)
			if (kind == "tamper" || kind == "truncated" || kind == "wrong_key") && err != nil {
				t.Fatalf("fixture did not reach archive authentication: %v", err)
			}
			if err == nil {
				keyIdentity := identity
				if kind == "wrong_key" {
					keyIdentity = recoveryIdentity(t)
				}
				stage := t.TempDir()
				err = Restore(op, fixtureTools, target, output, keyIdentity, receipt.PlaintextSHA256, receipt.PlaintextBytes, stage)
				assertNoStage(t, stage)
			} else if kind != "existing" {
				if _, statErr := os.Stat(output); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatal("failed download retained a partial file")
				}
			}
			if err == nil {
				t.Fatal("invalid remote recovery accepted")
			}
			if kind == "existing" {
				data, err := os.ReadFile(output)
				if err != nil || string(data) != "keep" {
					t.Fatal("preexisting download target overwritten")
				}
			}
			if actual := query(t, ctx, target, "SELECT count(*) FROM pg_tables WHERE schemaname='public';"); actual != "0" {
				t.Fatalf("invalid remote recovery mutated target: %s", actual)
			}
		})
	}
}
