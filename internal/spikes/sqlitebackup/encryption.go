package sqlitebackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

// Encrypt streams a stable snapshot to an age file, without buffering the DB.
func Encrypt(ctx context.Context, source, destination string, recipient age.Recipient) error {
	if recipient == nil {
		return errors.New("backup recipient is required")
	}
	return transform(ctx, source, destination, func(in io.Reader, out io.Writer) error {
		writer, err := age.Encrypt(out, recipient)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, in)
		return errors.Join(copyErr, writer.Close())
	})
}

// Decrypt reads ciphertext again, authenticates every chunk, and discards the
// plaintext destination on any error, including truncated/corrupted input.
func Decrypt(ctx context.Context, source, destination string, identity age.Identity) error {
	if identity == nil {
		return errors.New("recovery identity is required")
	}
	return transform(ctx, source, destination, func(in io.Reader, out io.Writer) error {
		reader, err := age.Decrypt(in, identity)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, reader)
		return err
	})
}

func transform(ctx context.Context, source, destination string, copyStream func(io.Reader, io.Writer) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	var out *os.File
	defer func() {
		err = errors.Join(err, in.Close())
		if out != nil {
			err = errors.Join(err, out.Close())
			if err != nil {
				err = errors.Join(err, removeFile(destination))
			}
		}
	}()
	out, err = os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("reserve destination: %w", err)
	}
	if err = copyStream(contextReader{ctx: ctx, reader: in}, out); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return out.Sync()
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

func Digest(path string) (digest string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
