// Package testinfra owns isolated, synthetic development fixtures only.
package testinfra

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const FlociImage = "floci/floci:2.1.0@sha256:f5aa8c18302cedb4f2385f5c4e455b3efc77fee6bf7b6e5d1712b2817ba102db"

type Floci struct {
	id       string // Exact ID returned by this invocation, never a name filter.
	Endpoint string
}

func (f *Floci) Stop() error {
	if f == nil || f.id == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", "rm", "--force", "--volumes", f.id).CombinedOutput()
	if err != nil {
		return fmt.Errorf("remove owned Floci: %w: %s", err, output)
	}
	f.id = ""
	return nil
}

// StartFloci retries ONLY the observed rootless host-bind collision, at most
// three times. docker run can create a container before networking fails;
// its exact returned ID is cleaned before retry. No other containers are swept.
func StartFloci(ctx context.Context) (*Floci, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("fixture startup requires a deadline")
	}
	for attempt := 1; attempt <= 3; attempt++ {
		var suffix [12]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, err
		}
		name := "private-registry-floci-" + hex.EncodeToString(suffix[:])
		output, err := exec.CommandContext(ctx, "docker", "run", "--detach", "--pull=never", "--name", name,
			"--user=1001:0", "--cpus=2", "--memory=512m", "--pids-limit=256", "--cap-drop=ALL",
			"--security-opt=no-new-privileges", "--publish", "127.0.0.1::4566",
			"--env", "LOCALSTACK_PARITY=false", "--env", "FLOCI_SERVICES_S3_ENFORCE_AUTH=true", FlociImage).CombinedOutput()
		fixture := &Floci{id: returnedContainerID(string(output))}
		if err != nil {
			owned := fixture.id != ""
			cleanupErr := fixture.Stop()
			if !owned || cleanupErr != nil || ctx.Err() != nil || !bindCollision(string(output)) || attempt == 3 {
				return nil, errors.Join(fmt.Errorf("start Floci: %w: %s", err, output), cleanupErr, ctx.Err())
			}
			continue
		}
		if fixture.id == "" {
			return nil, errors.New("Docker did not return an owned fixture ID")
		}
		port, err := exec.CommandContext(ctx, "docker", "port", fixture.id, "4566/tcp").Output()
		if err != nil {
			return nil, errors.Join(err, fixture.Stop())
		}
		fixture.Endpoint = "http://" + strings.TrimSpace(string(port))
		return fixture, nil
	}
	return nil, errors.New("fixture startup attempts exhausted")
}

func bindCollision(output string) bool {
	return strings.Contains(output, "RootlessKit PortManager.AddPort()") && strings.Contains(output, "bind: address already in use")
}

func returnedContainerID(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if len(line) != 64 {
			continue
		}
		if _, err := hex.DecodeString(line); err == nil {
			return line
		}
	}
	return ""
}
