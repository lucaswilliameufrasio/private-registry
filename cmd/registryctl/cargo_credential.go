package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"runtime"
	"strings"
)

// runCargoCredential implements Cargo's credential-provider protocol (v1).
// The registry issues separate read and write tokens, so the provider answers
// `read` with the read token and `publish`/`yank`/`unyank` with the write
// token. Tokens are read from files on every request and Cargo is told never
// to cache them; login and logout are refused because tokens are issued and
// revoked through the registry API.
//
// Cargo starts the provider as `registryctl --cargo-plugin` and sends the
// arguments configured in credential-alias inside every request, so one
// installed binary serves any number of registries:
//
//	[credential-alias]
//	private-registry = ["registryctl", "-index", "sparse+https://HOST/cargo/WORKSPACE/REPOSITORY/index/", "-read-token-file", "/path/read", "-write-token-file", "/path/write"]
//	[registries.private]
//	index = "sparse+https://HOST/cargo/WORKSPACE/REPOSITORY/index/"
//	credential-provider = "private-registry"
func runCargoCredential(in io.Reader, out io.Writer) error {
	if in == nil || out == nil {
		return errors.New("credential provider streams are required")
	}
	encoder := json.NewEncoder(out)
	if err := encoder.Encode(map[string][]int{"v": {1}}); err != nil {
		return errors.New("credential provider handshake could not be written")
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		response := cargoCredentialResponse(scanner.Bytes())
		if err := encoder.Encode(response); err != nil {
			return errors.New("credential provider response could not be written")
		}
	}
	if scanner.Err() != nil {
		return errors.New("credential provider request could not be read")
	}
	return nil
}

func cargoCredentialResponse(line []byte) map[string]any {
	refuse := func(kind, message string) map[string]any {
		failure := map[string]any{"kind": kind}
		if message != "" {
			failure["message"] = message
		}
		return map[string]any{"Err": failure}
	}
	var request struct {
		Version   int      `json:"v"`
		Kind      string   `json:"kind"`
		Operation string   `json:"operation"`
		Args      []string `json:"args"`
		Registry  struct {
			IndexURL string `json:"index-url"`
		} `json:"registry"`
	}
	if err := json.Unmarshal(line, &request); err != nil || request.Version != 1 {
		return refuse("other", "unsupported credential provider request")
	}
	flags := flag.NewFlagSet("cargo-credential", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	index := flags.String("index", "", "exact registry index URL these token files belong to")
	readFile := flags.String("read-token-file", "", "file holding the personal read token")
	writeFile := flags.String("write-token-file", "", "file holding the Cargo write token")
	if err := flags.Parse(request.Args); err != nil || flags.NArg() != 0 || *index == "" || (*readFile == "" && *writeFile == "") {
		return refuse("other", "credential-alias must pass -index and -read-token-file and/or -write-token-file")
	}
	// A token is only ever released for the index it was configured for:
	// reusing the alias for another registry yields nothing.
	if request.Registry.IndexURL != *index {
		return refuse("url-not-supported", "")
	}
	path := ""
	if request.Kind == "get" {
		switch request.Operation {
		case "read":
			path = *readFile
		case "publish", "yank", "unyank":
			path = *writeFile
		}
	}
	if path == "" {
		return refuse("operation-not-supported", "")
	}
	token, err := readTokenFile(path)
	if err != nil {
		return refuse("not-found", "")
	}
	return map[string]any{"Ok": map[string]any{"kind": "get", "token": token, "cache": "never", "operation_independent": false}}
}

// readTokenFile returns a single-line token. On Unix-like systems the file
// must not be accessible to group or others.
func readTokenFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return "", errors.New("token file is unavailable")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("token file must not be accessible to group or others")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("token file is unavailable")
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(contents), "\n"), "\r")
	if token == "" || strings.ContainsAny(token, " \t\r\n\x00") {
		return "", errors.New("token file is malformed")
	}
	return token, nil
}
