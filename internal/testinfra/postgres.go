//go:build integration

package testinfra

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const PostgresImage = "postgres:18.6-alpine3.23@sha256:8c80c49c67052d82f9aaf4ee1f1881c8926b445a1cc916892934845eb8c24204"

var containerIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Postgres struct {
	containerID string
	socketDir   string
}

func (p *Postgres) DSN() string {
	if p == nil || p.socketDir == "" {
		return ""
	}
	return fmt.Sprintf("host=%s port=5432 user=postgres dbname=postgres sslmode=disable", p.socketDir)
}

func StartPostgres(ctx context.Context) (*Postgres, error) {
	if ctx == nil {
		return nil, errors.New("PostgreSQL fixture context is required")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("PostgreSQL fixture requires a deadline")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, errors.New("generate isolated PostgreSQL fixture identity")
	}
	name := "private-registry-pg-" + hex.EncodeToString(suffix[:])
	socketDir, err := os.MkdirTemp("/tmp/opencode", "private-registry-pg-socket-")
	if err != nil {
		return nil, errors.New("create isolated PostgreSQL socket directory")
	}
	fixture := &Postgres{socketDir: socketDir}
	// The container runs with --network=none. The sticky, non-listable socket
	// directory is writable by the mapped postgres UID; the socket itself is
	// test-only and reachable through this unpredictable local path.
	if err := os.Chmod(socketDir, 0o1733); err != nil {
		return nil, errors.Join(errors.New("secure isolated PostgreSQL socket directory"), fixture.Stop())
	}

	output, err := exec.CommandContext(ctx, "docker", "run", "--detach", "--pull=never", "--name", name,
		"--network=none", "--cpus=2", "--memory=512m", "--pids-limit=256",
		"--security-opt=no-new-privileges", "--mount", "type=bind,source="+socketDir+",target=/var/run/postgresql",
		"--env", "POSTGRES_HOST_AUTH_METHOD=trust", PostgresImage).CombinedOutput()
	fixture.containerID = returnedContainerID(string(output))
	if err != nil {
		cleanupErr := fixture.Stop()
		return nil, errors.Join(fmt.Errorf("start isolated PostgreSQL: %w", safeDockerError(output)), cleanupErr)
	}
	if fixture.containerID == "" {
		return nil, errors.Join(errors.New("Docker did not return an owned PostgreSQL fixture ID"), fixture.Stop())
	}

	if err := waitForPostgres(ctx, fixture.containerID); err != nil {
		return nil, errors.Join(err, fixture.Stop())
	}
	if err := restrictPostgresSocketDirectory(ctx, fixture.containerID); err != nil {
		return nil, errors.Join(err, fixture.Stop())
	}
	return fixture, nil
}

func (p *Postgres) Stop() error {
	if p == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var stopErr error
	containerWasOwned := p.containerID != ""
	if p.containerID != "" {
		if output, err := exec.CommandContext(ctx, "docker", "rm", "--force", "--volumes", p.containerID).CombinedOutput(); err != nil {
			stopErr = errors.Join(stopErr, fmt.Errorf("remove owned PostgreSQL fixture: %w", safeDockerError(output)))
			return stopErr
		}
		p.containerID = ""
	}
	if p.socketDir != "" {
		if containerWasOwned {
			if err := makeSocketDirectoryRemovable(ctx, p.socketDir); err != nil {
				stopErr = errors.Join(stopErr, err)
				return stopErr
			}
		}
		if err := os.RemoveAll(p.socketDir); err != nil {
			stopErr = errors.Join(stopErr, fmt.Errorf("remove owned PostgreSQL socket directory: %w", err))
		} else {
			p.socketDir = ""
		}
	}
	return stopErr
}

func makeSocketDirectoryRemovable(ctx context.Context, socketDir string) error {
	output, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--pull=never", "--network=none",
		"--user=postgres", "--mount", "type=bind,source="+socketDir+",target=/var/run/postgresql",
		"--entrypoint", "/bin/chmod", PostgresImage, "0770", "/var/run/postgresql").CombinedOutput()
	if err != nil {
		return fmt.Errorf("make owned PostgreSQL socket directory removable: %w", safeDockerError(output))
	}
	return nil
}

func restrictPostgresSocketDirectory(ctx context.Context, containerID string) error {
	output, err := exec.CommandContext(ctx, "docker", "exec", "--user=postgres", containerID,
		"/bin/chmod", "0770", "/var/run/postgresql").CombinedOutput()
	if err != nil {
		return fmt.Errorf("restrict owned PostgreSQL socket directory: %w", safeDockerError(output))
	}
	return nil
}

func waitForPostgres(ctx context.Context, containerID string) error {
	var lastOutput []byte
	for {
		// The initialization server accepts Unix sockets only. TCP loopback becomes
		// reachable only after the final server has replaced it.
		output, err := exec.CommandContext(ctx, "docker", "exec", containerID,
			"psql", "--host=127.0.0.1", "--username=postgres", "--no-password",
			"--tuples-only", "--no-align", "--command=SELECT 1").CombinedOutput()
		if err == nil && strings.TrimSpace(string(output)) == "1" {
			return nil
		}
		lastOutput = output
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			diagnosticCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			logs, _ := exec.CommandContext(diagnosticCtx, "docker", "logs", "--tail", "40", containerID).CombinedOutput()
			cancel()
			if len(logs) > 4096 {
				logs = logs[len(logs)-4096:]
			}
			return fmt.Errorf("isolated PostgreSQL did not become reachable: %s\nfixture logs:\n%s",
				strings.TrimSpace(string(lastOutput)), strings.TrimSpace(string(logs)))
		case <-timer.C:
		}
	}
}

func returnedContainerID(output string) string {
	value := strings.TrimSpace(output)
	if !containerIDPattern.MatchString(value) {
		return ""
	}
	return value
}

func safeDockerError(output []byte) error {
	if len(output) == 0 {
		return errors.New("Docker command failed")
	}
	return errors.New("Docker command failed; diagnostic output was suppressed")
}
