package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCargoCredentialSeparatesReadAndWriteTokens(t *testing.T) {
	directory := t.TempDir()
	readFile := filepath.Join(directory, "read")
	writeFile := filepath.Join(directory, "write")
	exposed := filepath.Join(directory, "exposed")
	for path, contents := range map[string]string{readFile: "synthetic-read-token\n", writeFile: "synthetic-write-token", exposed: "synthetic-exposed-token"} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(exposed, 0o644); err != nil {
		t.Fatal(err)
	}
	const index = "sparse+https://registry.example/cargo/w/r/index/"
	configured := []string{"-index", index, "-read-token-file", readFile, "-write-token-file", writeFile}
	requestWith := func(args []string, kind, operation, url string) string {
		encoded, err := json.Marshal(map[string]any{"v": 1, "kind": kind, "operation": operation, "registry": map[string]string{"index-url": url}, "args": args})
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded) + "\n"
	}
	request := func(kind, operation, url string) string { return requestWith(configured, kind, operation, url) }
	input := request("get", "read", index) + request("get", "publish", index) + request("get", "yank", index) + request("get", "unyank", index) + request("get", "owners", index) + request("login", "", index) + request("logout", "", index) + request("get", "read", "sparse+https://other.example/index/") + "not json\n"
	var output bytes.Buffer
	if err := runCargoCredential(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 10 || lines[0] != `{"v":[1]}` {
		t.Fatalf("unexpected provider output: %q", output.String())
	}
	token := func(line string) string {
		var response struct {
			Ok struct {
				Token                string `json:"token"`
				Cache                string `json:"cache"`
				OperationIndependent *bool  `json:"operation_independent"`
			}
		}
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			t.Fatal(err)
		}
		if response.Ok.Token != "" && (response.Ok.Cache != "never" || response.Ok.OperationIndependent == nil || *response.Ok.OperationIndependent) {
			t.Fatalf("token response may be cached or reused across operations: %s", line)
		}
		return response.Ok.Token
	}
	for position, want := range map[int]string{1: "synthetic-read-token", 2: "synthetic-write-token", 3: "synthetic-write-token", 4: "synthetic-write-token"} {
		if got := token(lines[position]); got != want {
			t.Errorf("response %d token = %q, want %q", position, got, want)
		}
	}
	for position, want := range map[int]string{5: "operation-not-supported", 6: "operation-not-supported", 7: "operation-not-supported", 8: "url-not-supported", 9: "other"} {
		if token(lines[position]) != "" || !strings.Contains(lines[position], `"kind":"`+want+`"`) || strings.Contains(lines[position], "synthetic-") {
			t.Errorf("response %d = %s, want refusal %s", position, lines[position], want)
		}
	}

	// A read-only configuration never yields a write token, an exposed token
	// file is refused instead of used, and an alias without token files or
	// index releases nothing.
	output.Reset()
	input = requestWith([]string{"-index", index, "-read-token-file", exposed}, "get", "read", index) +
		requestWith([]string{"-index", index, "-read-token-file", readFile}, "get", "publish", index) +
		requestWith([]string{"-index", index}, "get", "read", index) +
		requestWith([]string{"-read-token-file", readFile}, "get", "read", index) +
		requestWith(nil, "get", "read", index)
	if err := runCargoCredential(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	refusals := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(refusals) != 6 || strings.Contains(output.String(), "synthetic-") || !strings.Contains(refusals[1], "not-found") || !strings.Contains(refusals[2], "operation-not-supported") {
		t.Fatalf("a token was released for an unsafe or incomplete configuration: %s", output.String())
	}
	for _, line := range refusals[3:] {
		if !strings.Contains(line, `"kind":"other"`) {
			t.Errorf("incomplete alias was not refused: %s", line)
		}
	}
}
