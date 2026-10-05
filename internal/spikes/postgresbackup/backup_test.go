package postgresbackup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestLimitsAndCancellation(t *testing.T) {
	var output bytes.Buffer
	w := boundedWriter{ctx: context.Background(), writer: &output, remaining: 3}
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("d")); err == nil || output.String() != "abc" {
		t.Fatal("size limit not enforced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.ctx = ctx
	if _, err := w.Write(nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}

// Unit-level subprocess protocol harness for tool diagnostics/version parsing;
// actual pg_dump/pg_restore and SQL semantics are tested against PostgreSQL.
func TestToolProcessHelper(t *testing.T) {
	mode := os.Getenv("PRIVATE_REGISTRY_PG_TOOL_HELPER")
	if mode == "" {
		return
	}
	args := os.Args
	for index, value := range args {
		if value != "--" || index+2 >= len(args) {
			continue
		}
		tool, option := args[index+1], args[index+2]
		if option == "--version" {
			if mode == "wait_version" {
				if err := os.WriteFile(os.Getenv("PRIVATE_REGISTRY_PG_TOOL_STARTED"), []byte("started"), 0o600); err != nil {
					os.Exit(2)
				}
				time.Sleep(30 * time.Second)
				os.Exit(2)
			}
			if mode == "malformed" {
				_, _ = io.WriteString(os.Stdout, "unexpected tools response\n")
			} else {
				_, _ = io.WriteString(os.Stdout, tool+" (PostgreSQL) 18.6\n")
			}
			os.Exit(0)
		}
		_, _ = io.WriteString(os.Stdout, "synthetic tool payload")
		if mode == "warning" {
			_, _ = io.WriteString(os.Stderr, "warning: synthetic diagnostic\n")
		}
		os.Exit(0)
	}
	os.Exit(2)
}

func TestCancellationWhileReadingToolVersion(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PRIVATE_REGISTRY_PG_TOOL_HELPER", "wait_version")
	started := filepath.Join(t.TempDir(), "started")
	t.Setenv("PRIVATE_REGISTRY_PG_TOOL_STARTED", started)
	tools := Tools{Executable: binary, Prefix: []string{"-test.run=^TestToolProcessHelper$", "--"}, ExpectedMajor: 18}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- tools.CheckVersions(ctx) }()
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if err := ctx.Err(); err != nil {
			t.Fatalf("helper did not start: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("tool cancellation lost (signal killed alone is insufficient): %v", err)
	}
}

func TestWarningsAndMalformedVersionsAreFatal(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tools := Tools{Executable: binary, Prefix: []string{"-test.run=^TestToolProcessHelper$", "--"}, ExpectedMajor: 18}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t.Run("malformed version", func(t *testing.T) {
		t.Setenv("PRIVATE_REGISTRY_PG_TOOL_HELPER", "malformed")
		if err := tools.CheckVersions(ctx); err == nil || !strings.Contains(err.Error(), "unexpected pg_dump version") {
			t.Fatalf("malformed version accepted: %v", err)
		}
	})
	t.Run("successful exit with warning", func(t *testing.T) {
		t.Setenv("PRIVATE_REGISTRY_PG_TOOL_HELPER", "warning")
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(t.TempDir(), "warning.age")
		receipt, err := Dump(ctx, tools, "fixture", "", destination, identity.Recipient(), 1024)
		if err == nil || !strings.Contains(err.Error(), "warnings are fatal") || receipt.PlaintextBytes != 0 {
			t.Fatalf("warning accepted as a valid receipt: %+v %v", receipt, err)
		}
		if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("warning left a valid-looking ciphertext")
		}
	})
}

func TestDiagnosticsAreBounded(t *testing.T) {
	var output cappedBuffer
	if _, err := io.Copy(&output, bytes.NewReader(bytes.Repeat([]byte("x"), 10000))); err != nil {
		t.Fatal(err)
	}
	if len(output.String()) != 4096 || output.total != 10000 {
		t.Fatal("tool diagnostics are not bounded")
	}
}

func TestInvalidPolicyBeforeToolExecution(t *testing.T) {
	tools := Tools{Executable: "must-not-execute", ExpectedMajor: 18}
	if err := tools.CheckVersions(context.Background()); err == nil {
		t.Fatal("unbounded context accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Dump(ctx, tools, "-injected", "", "unused", nil, 1); err == nil {
		t.Fatal("invalid dump accepted")
	}
	if err := Restore(ctx, tools, "fixture", "unused", nil, "invalid", 1, t.TempDir()); err == nil {
		t.Fatal("invalid restore accepted")
	}
	if err := (Tools{}).validate(ctx); err == nil {
		t.Fatal("implicit tools accepted")
	}
	for _, snapshot := range []string{"../../snapshot", "--help", "1;DROP", ""} {
		if snapshotName.MatchString(snapshot) {
			t.Fatalf("unsafe exported snapshot identifier accepted: %s", snapshot)
		}
	}
}
