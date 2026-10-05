// Package postgresbackup is a phase-0 logical-backup experiment, not a
// production adapter, installation manifest, or persistent job runner.
package postgresbackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
)

// Tools permits the isolated fixture to run tools via docker exec. Executable
// and Prefix are trusted operator configuration, not user-controlled input.
// Credentials must be supplied outside arguments; the fixture uses a local
// Unix socket with a test-only database role inside its own container.
type Tools struct {
	Executable    string
	Prefix        []string
	ExpectedMajor int
}

type Receipt struct {
	PlaintextSHA256 string
	PlaintextBytes  int64
	ToolsMajor      int
}

var databaseName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
var snapshotName = regexp.MustCompile(`^[A-Fa-f0-9]+-[A-Fa-f0-9]+-[0-9]+$`)
var toolVersion = regexp.MustCompile(`^pg_(dump|restore) \(PostgreSQL\) ([0-9]+)\.[^\n]+\n?$`)

func (t Tools) validate(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("backup tools require a context deadline")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if t.Executable == "" || t.ExpectedMajor < 10 {
		return errors.New("explicit executable and expected server major required")
	}
	return nil
}

func (t Tools) command(ctx context.Context, tool string, args ...string) *exec.Cmd {
	arguments := append(append([]string{}, t.Prefix...), tool)
	command := exec.CommandContext(ctx, t.Executable, append(arguments, args...)...)
	command.WaitDelay = 2 * time.Second
	return command
}

// CheckVersions intentionally accepts only same-major tools in this spike.
// PostgreSQL's broader upgrade compatibility is not claimed or distributed.
func (t Tools) CheckVersions(ctx context.Context) error {
	if err := t.validate(ctx); err != nil {
		return err
	}
	for _, tool := range []string{"pg_dump", "pg_restore"} {
		var output cappedBuffer
		if err := run(t.command(ctx, tool, "--version"), &output, nil); err != nil {
			return fmt.Errorf("%s version: %w", tool, errors.Join(err, ctx.Err()))
		}
		match := toolVersion.FindStringSubmatch(output.String())
		if output.total > 4096 || match == nil || "pg_"+match[1] != tool {
			return fmt.Errorf("unexpected %s version response", tool)
		}
		major, _ := strconv.Atoi(match[2])
		if major != t.ExpectedMajor {
			return fmt.Errorf("%s major %d does not match server major %d", tool, major, t.ExpectedMajor)
		}
	}
	return nil
}

// Dump streams pg_dump's custom archive directly into age. A nonempty stderr
// (including a warning with exit status 0) fails the experiment; no receipt is
// considered valid and the owned ciphertext file is removed on failure.
// snapshot can be an exported snapshot held open by a separate connection.
func Dump(ctx context.Context, tools Tools, database, snapshot, destination string, recipient age.Recipient, maxBytes int64) (receipt Receipt, err error) {
	if !databaseName.MatchString(database) || (snapshot != "" && !snapshotName.MatchString(snapshot)) || recipient == nil || maxBytes <= 0 {
		return receipt, errors.New("valid fixture database/snapshot, recipient and positive dump limit required")
	}
	if err := tools.CheckVersions(ctx); err != nil {
		return receipt, err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return receipt, err
	}
	defer func() {
		err = errors.Join(err, output.Close())
		if err != nil {
			err = errors.Join(err, os.Remove(destination))
			receipt = Receipt{}
		}
	}()
	sealed, err := age.Encrypt(output, recipient)
	if err != nil {
		return receipt, err
	}
	hash := sha256.New()
	writer := &boundedWriter{ctx: ctx, writer: io.MultiWriter(sealed, hash), remaining: maxBytes}
	arguments := []string{"--username=postgres", "--no-password", "--format=custom", "--no-owner", "--no-acl", "--dbname=" + database}
	if snapshot != "" {
		arguments = append(arguments, "--snapshot="+snapshot)
	}
	err = run(tools.command(ctx, "pg_dump", arguments...), writer, nil)
	err = errors.Join(err, sealed.Close(), ctx.Err())
	if err != nil {
		return receipt, err
	}
	if err := output.Sync(); err != nil {
		return receipt, err
	}
	return Receipt{hex.EncodeToString(hash.Sum(nil)), writer.bytes, tools.ExpectedMajor}, nil
}

// Restore authenticates the ENTIRE archive and its independent digest before
// invoking pg_restore. Decrypting directly into pg_restore could let it commit
// before authentication of a trailing age chunk fails. The private bounded
// plaintext staging file is always removed; target must be an isolated empty
// database. --single-transaction prevents a bad archive leaving partial DDL.
func Restore(ctx context.Context, tools Tools, database, ciphertext string, identity age.Identity, digest string, maxBytes int64, stagingDirectory string) (err error) {
	expected, digestErr := hex.DecodeString(digest)
	if !databaseName.MatchString(database) || identity == nil || digestErr != nil || len(expected) != sha256.Size || maxBytes <= 0 {
		return errors.New("valid fixture database, identity, SHA-256 and positive restore limit required")
	}
	if err := tools.CheckVersions(ctx); err != nil {
		return err
	}
	input, err := os.Open(ciphertext)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	plaintext, err := age.Decrypt(input, identity)
	if err != nil {
		return err
	}
	stage, err := os.CreateTemp(stagingDirectory, "private-registry-pg-restore-*.dump")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, stage.Close(), os.Remove(stage.Name())) }()
	hash := sha256.New()
	writer := &boundedWriter{ctx: ctx, writer: io.MultiWriter(stage, hash), remaining: maxBytes}
	if _, err := io.Copy(writer, plaintext); err != nil {
		return err
	}
	if !bytes.Equal(hash.Sum(nil), expected) {
		return errors.New("decrypted dump digest mismatch")
	}
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// No --clean: the isolated target must be fresh, not production data.
	return errors.Join(run(tools.command(ctx, "pg_restore", "--username=postgres", "--no-password", "--no-owner", "--no-acl",
		"--single-transaction", "--exit-on-error", "--dbname="+database), io.Discard, stage), ctx.Err())
}

func run(command *exec.Cmd, output io.Writer, input io.Reader) error {
	var diagnostic cappedBuffer
	command.Stdout, command.Stdin, command.Stderr = output, input, &diagnostic
	err := command.Run()
	if diagnostic.total != 0 {
		// This experiment uses synthetic data only. Never print process arguments
		// or credentials; production diagnostic redaction is a separate contract.
		err = errors.Join(err, fmt.Errorf("tool diagnostic (warnings are fatal): %s", strings.TrimSpace(diagnostic.String())))
	}
	return err
}

type cappedBuffer struct {
	buffer bytes.Buffer
	total  int64
}

func (b *cappedBuffer) String() string { return b.buffer.String() }

func (b *cappedBuffer) Write(data []byte) (int, error) {
	b.total += int64(len(data))
	if space := 4096 - b.buffer.Len(); space > 0 {
		_, _ = b.buffer.Write(data[:min(len(data), space)])
	}
	return len(data), nil
}

type boundedWriter struct {
	ctx       context.Context
	writer    io.Writer
	remaining int64
	bytes     int64
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(data)) > w.remaining {
		return 0, errors.New("plaintext exceeds backup limit")
	}
	n, err := w.writer.Write(data)
	w.bytes += int64(n)
	w.remaining -= int64(n)
	return n, err
}
