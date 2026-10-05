package testinfra

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestObservedRootlessCollisionClassification(t *testing.T) {
	observed := "error while calling RootlessKit PortManager.AddPort(): listen tcp4 127.0.0.1:32812: bind: address already in use"
	if !bindCollision(observed) {
		t.Fatal("observed rootless collision not recognized")
	}
	for _, other := range []string{"permission denied", "image absent", "connection refused", "name already in use by container", "bind: address already in use", "RootlessKit PortManager.AddPort(): canceled"} {
		if bindCollision(other) {
			t.Fatalf("unrelated failure would be retried: %s", other)
		}
	}
}

// Unit subprocess protocol harness, not an emulated S3 backend. Full integration
// tests still run actual Docker/Floci. This deterministically reproduces Docker
// returning a created ID followed by the observed RootlessKit bind failure.
func TestStartupCleansCreatedContainerBeforeBoundedRetry(t *testing.T) {
	for _, mode := range []string{"collision_once", "always_collision", "cleanup_failure", "other_failure"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			log := filepath.Join(directory, "calls")
			state := filepath.Join(directory, "attempt")
			t.Setenv("TEST_DOCKER_LOG", log)
			t.Setenv("TEST_DOCKER_STATE", state)
			t.Setenv("TEST_DOCKER_MODE", mode)
			t.Setenv("PATH", directory+":"+os.Getenv("PATH"))
			script := `#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$TEST_DOCKER_LOG"
case "$1" in
  run)
    n=0
    if [[ -f "$TEST_DOCKER_STATE" ]]; then n=$(cat "$TEST_DOCKER_STATE"); fi
    n=$((n+1))
    printf '%s' "$n" > "$TEST_DOCKER_STATE"
    if [[ "$TEST_DOCKER_MODE" == other_failure ]]; then echo 'permission denied' >&2; exit 125; fi
    printf '%064d\n' "$n"
    if [[ "$TEST_DOCKER_MODE" != collision_once || "$n" == 1 ]]; then
      echo 'RootlessKit PortManager.AddPort(): listen tcp4 127.0.0.1:32812: bind: address already in use' >&2
      exit 125
    fi
    ;;
  rm) if [[ "$TEST_DOCKER_MODE" == cleanup_failure ]]; then echo 'cleanup denied' >&2; exit 1; fi ;;
  port) echo '127.0.0.1:4566' ;;
  *) exit 1 ;;
esac
`
			if err := os.WriteFile(filepath.Join(directory, "docker"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			fixture, err := StartFloci(ctx)
			if mode == "collision_once" {
				if err != nil || fixture.Endpoint != "http://127.0.0.1:4566" {
					t.Fatalf("retry failed: %v", err)
				}
				if err := fixture.Stop(); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("fixture failure incorrectly accepted")
			}
			data, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			calls := strings.Split(strings.TrimSpace(string(data)), "\n")
			runs, removes := 0, 0
			for _, call := range calls {
				if strings.HasPrefix(call, "run ") {
					runs++
				} else if strings.HasPrefix(call, "rm ") {
					removes++
					if !strings.HasPrefix(call, "rm --force --volumes ") || returnedContainerID(strings.TrimPrefix(call, "rm --force --volumes ")) == "" {
						t.Fatalf("cleanup targeted non-owned ID: %s", call)
					}
				}
			}
			want := map[string][2]int{"collision_once": {2, 2}, "always_collision": {3, 3}, "cleanup_failure": {1, 1}, "other_failure": {1, 0}}[mode]
			if runs != want[0] || removes != want[1] {
				t.Fatalf("incorrect bounded lifecycle: runs=%d removes=%d calls=%v", runs, removes, calls)
			}
			if mode == "collision_once" && !strings.HasPrefix(calls[1], "rm ") {
				t.Fatal("failed container was not cleaned before retry")
			}
		})
	}
}

func TestOnlyExactReturnedContainerIDsAreOwned(t *testing.T) {
	id := strings.Repeat("a", 64)
	if got := returnedContainerID(id + "\ndocker: networking failed"); got != id {
		t.Fatal("created container ID lost")
	}
	for _, output := range []string{"private-registry-floci-user-data", "abcdef", strings.Repeat("z", 64), "--all"} {
		if returnedContainerID(output) != "" {
			t.Fatal("non-ID output treated as owned resource")
		}
	}
	if _, err := StartFloci(context.Background()); err == nil {
		t.Fatal("unbounded startup accepted")
	}
}
