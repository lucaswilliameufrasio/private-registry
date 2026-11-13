package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestReadTerminalLineDoesNotPrefetchFollowingInput(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	if _, err := writer.Write([]byte("first.admin\r\nsecond line\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	first, err := readTerminalLine(reader, &output, "Login: ")
	if err != nil {
		t.Fatal(err)
	}
	second, err := readTerminalLine(reader, &output, "Name: ")
	if err != nil {
		t.Fatal(err)
	}
	if first != "first.admin" || second != "second line" {
		t.Fatalf("unexpected prompt lines: first=%q second=%q", first, second)
	}
	if output.String() != "Login: Name: " {
		t.Fatalf("unexpected prompts: %q", output.String())
	}
}

func TestRequireInteractiveTerminalRejectsPipes(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})

	err = requireInteractiveTerminal(int(reader.Fd()), int(writer.Fd()))
	if err == nil || !strings.Contains(err.Error(), "requires an interactive terminal") {
		t.Fatalf("pipe descriptors unexpectedly passed terminal check: %v", err)
	}
}
