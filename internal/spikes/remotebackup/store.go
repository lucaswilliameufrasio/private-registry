// Package remotebackup proves encrypted S3 roundtrips against an isolated real
// Floci. It is not a production storage adapter, backup manifest, or job queue.
package remotebackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const PartSize = 5 * 1024 * 1024

type Store struct {
	Client *s3.Client
	Bucket string
}

type Receipt struct {
	PlaintextSHA256 string
	PlaintextBytes  int64
	CiphertextBytes int64
	Parts           int
}

// NewClient is intentionally restricted to literal loopback addresses: the
// phase-0 fixture must never pick up cloud credentials or a production bucket.
func NewClient(endpoint, accessKey, secretKey string) (*s3.Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("invalid fixture endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	port, portErr := strconv.Atoi(u.Port())
	if (u.Scheme != "http" && u.Scheme != "https") || ip == nil || !ip.IsLoopback() ||
		portErr != nil || port < 1 || port > 65535 || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return nil, errors.New("fixture endpoint must be a literal loopback host and port, without credentials or paths")
	}
	if accessKey == "" || secretKey == "" {
		return nil, errors.New("explicit fixture credentials required")
	}
	return s3.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},
		Retryer:     func() aws.Retryer { return retry.NewStandard(func(o *retry.StandardOptions) { o.MaxAttempts = 2 }) },
	}, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(strings.TrimSuffix(endpoint, "/"))
		o.UsePathStyle = true
	}), nil
}

func (s Store) validate(ctx context.Context, key string) error {
	if s.Client == nil || s.Bucket == "" || key == "" {
		return errors.New("client, fixture bucket and object key required")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("remote operation requires a context deadline")
	}
	return ctx.Err()
}

// Upload encrypts the snapshot into a pipe and sends bounded multipart chunks.
// Only one 5 MiB ciphertext buffer is reused; no local ciphertext copy is made.
// afterPart is an observation/failure-injection hook, not an approval mechanism.
func (s Store) Upload(ctx context.Context, snapshot, key string, recipient age.Recipient, afterPart func(int) error) (receipt Receipt, err error) {
	if err := s.validate(ctx, key); err != nil {
		return receipt, err
	}
	if recipient == nil {
		return receipt, errors.New("backup recipient required")
	}
	input, err := os.Open(snapshot)
	if err != nil {
		return receipt, err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	created, err := s.Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(s.Bucket), Key: aws.String(key), ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return receipt, fmt.Errorf("start multipart: %w", err)
	}
	completed := false
	defer func() {
		if completed {
			return
		}
		// Cancellation must not prevent cleanup. A bounded detached context can
		// attempt abort, but failures still require future persistent reconciliation.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, abortErr := s.Client.AbortMultipartUpload(cleanup, &s3.AbortMultipartUploadInput{
			Bucket: aws.String(s.Bucket), Key: aws.String(key), UploadId: created.UploadId,
		})
		err = errors.Join(err, abortErr)
	}()

	reader, writer := io.Pipe()
	type encryptionResult struct {
		digest string
		bytes  int64
		err    error
	}
	done := make(chan encryptionResult, 1)
	go func() {
		hash := sha256.New()
		sealed, encryptErr := age.Encrypt(writer, recipient)
		var count int64
		if encryptErr == nil {
			count, encryptErr = io.Copy(sealed, io.TeeReader(contextReader{ctx, input}, hash))
			encryptErr = errors.Join(encryptErr, sealed.Close())
		}
		_ = writer.CloseWithError(encryptErr)
		done <- encryptionResult{hex.EncodeToString(hash.Sum(nil)), count, encryptErr}
	}()
	var result encryptionResult
	received := false
	defer func() {
		_ = reader.CloseWithError(err)
		if !received {
			result = <-done
		}
		err = errors.Join(err, result.err)
		if err == nil {
			receipt.PlaintextSHA256 = result.digest
			receipt.PlaintextBytes = result.bytes
		}
	}()

	buffer := make([]byte, PartSize)
	parts := make([]types.CompletedPart, 0)
	for partNumber := int32(1); ; partNumber++ {
		if err := ctx.Err(); err != nil {
			return receipt, err
		}
		n, readErr := io.ReadFull(reader, buffer)
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return receipt, readErr
		}
		if n == 0 {
			break
		}
		if partNumber > 10000 {
			return receipt, errors.New("multipart part limit exceeded")
		}
		part, uploadErr := s.Client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: aws.String(s.Bucket), Key: aws.String(key), UploadId: created.UploadId,
			PartNumber: aws.Int32(partNumber), Body: bytes.NewReader(buffer[:n]), ContentLength: aws.Int64(int64(n)),
		})
		if uploadErr != nil {
			return receipt, fmt.Errorf("upload part: %w", uploadErr)
		}
		parts = append(parts, types.CompletedPart{PartNumber: aws.Int32(partNumber), ETag: part.ETag})
		receipt.Parts++
		receipt.CiphertextBytes += int64(n)
		if afterPart != nil {
			if err := afterPart(receipt.Parts); err != nil {
				return receipt, err
			}
		}
		if readErr != nil {
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return receipt, err
	}
	// Ciphertext EOF is not sufficient: the producer must confirm successful
	// encryption before any multipart completion is sent to the server.
	result = <-done
	received = true
	if result.err != nil {
		return receipt, result.err
	}
	_, err = s.Client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: aws.String(s.Bucket), Key: aws.String(key), UploadId: created.UploadId,
		IfNoneMatch: aws.String("*"), MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
	if err != nil {
		return receipt, fmt.Errorf("complete multipart: %w", err)
	}
	completed = true
	return receipt, nil
}

// Restore fetches the remote object afresh, authenticates age, checks the
// independent snapshot digest and a plaintext limit, then syncs a new file.
// Failure removes any partial plaintext, never a pre-existing destination.
func (s Store) Restore(ctx context.Context, key, destination string, identity age.Identity, digest string, maxBytes int64) (err error) {
	if err := s.validate(ctx, key); err != nil {
		return err
	}
	expected, err := hex.DecodeString(digest)
	if err != nil || len(expected) != sha256.Size || maxBytes <= 0 || maxBytes == math.MaxInt64 || identity == nil {
		return errors.New("identity, SHA-256 digest and bounded positive plaintext limit required")
	}
	object, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key)})
	if err != nil {
		return fmt.Errorf("read remote backup: %w", err)
	}
	var output *os.File
	defer func() {
		err = errors.Join(err, object.Body.Close())
		if output != nil {
			err = errors.Join(err, output.Close())
			if err != nil {
				err = errors.Join(err, os.Remove(destination))
			}
		}
	}()
	plaintext, err := age.Decrypt(contextReader{ctx, object.Body}, identity)
	if err != nil {
		return err
	}
	output, err = os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	count, err := io.Copy(io.MultiWriter(output, hash), io.LimitReader(plaintext, maxBytes+1))
	if err != nil {
		return err
	}
	if count > maxBytes {
		return errors.New("restored plaintext exceeds limit")
	}
	if !bytes.Equal(hash.Sum(nil), expected) {
		return errors.New("restored snapshot digest mismatch")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return output.Sync()
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}
