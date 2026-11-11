// registryctl provides client-side operations; it does not start the server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"private-registry/internal/gomod"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	// Cargo starts a credential provider with only --cargo-plugin; the
	// arguments configured in credential-alias arrive inside each request.
	if len(args) == 1 && args[0] == "--cargo-plugin" {
		return runCargoCredential(os.Stdin, out)
	}
	if len(args) >= 2 && args[0] == "publish" && args[1] == "go" {
		return runPublishGo(ctx, args[2:], out)
	}
	if len(args) >= 2 && args[0] == "publication" && (args[1] == "status" || args[1] == "finalize") {
		return runPublicationAction(ctx, args[1], args[2:], out)
	}
	if len(args) < 2 || args[0] != "pack" || args[1] != "go" || out == nil {
		return errors.New("usage: registryctl {pack go|publish go} [options]; Cargo runs the credential provider as registryctl --cargo-plugin")
	}
	flags := flag.NewFlagSet("pack go", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("dir", "", "module directory")
	version := flags.String("version", "", "canonical module version")
	path := flags.String("out", "", "new output ZIP path")
	if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 || *dir == "" || *version == "" || *path == "" {
		return errors.New("usage: registryctl pack go -dir DIRECTORY -version VERSION -out FILE")
	}
	file, err := os.OpenFile(*path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return errors.New("new output ZIP could not be created")
	}
	packCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	packed, packErr := gomod.PackDirectory(packCtx, *dir, *version, file, 10000)
	createdInfo, statErr := file.Stat()
	closeErr := file.Close()
	if packErr != nil || closeErr != nil || statErr != nil {
		pathInfo, pathErr := os.Lstat(*path)
		if pathErr == nil && statErr == nil && os.SameFile(createdInfo, pathInfo) {
			pathErr = os.Remove(*path)
		}
		return errors.Join(packErr, closeErr, statErr, pathErr)
	}
	result := struct {
		ModulePath string `json:"module_path"`
		Version    string `json:"version"`
		ZipSize    int64  `json:"zip_size"`
		ZipSHA256  string `json:"zip_sha256"`
	}{packed.ModulePath, packed.Version, packed.ZipSize, packed.ZipSHA256}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return errors.New("archive was created but its metadata could not be written")
	}
	return nil
}
