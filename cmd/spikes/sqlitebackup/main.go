package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"private-registry/internal/spikes/sqlitebackup"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sqlite backup spike:", err)
		os.Exit(1)
	}
}

func run() (err error) {
	directory, err := os.MkdirTemp("/tmp/opencode", "private-registry-sqlite-")
	if err != nil {
		return err
	}
	// Only this invocation's synthetic directory; report cleanup failures too.
	defer func() { err = errors.Join(err, os.RemoveAll(directory)) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	report, err := sqlitebackup.Experiment(ctx, directory)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
