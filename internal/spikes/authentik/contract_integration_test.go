//go:build integration

package authentik

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const authentikImage = "ghcr.io/goauthentik/server@sha256:ab9b4e8cc4ab3f8d1198d2db6aeea66bafea1963b3f2843589e0d163f97d9849"

var fixture struct {
	project    string
	compose    string
	envFile    string
	serverID   string
	workerID   string
	secrets    []string
	packageDir string
}

type contractReport struct {
	AuthentikVersion                     string             `json:"authentik_version"`
	OIDCAlgorithm                        string             `json:"oidc_algorithm"`
	OIDCSignatureVerified                bool               `json:"oidc_signature_verified"`
	OIDCSubjectMatchesSCIMExternalID     bool               `json:"oidc_subject_matches_scim_external_id"`
	SCIMDeactivationApplied              bool               `json:"scim_deactivation_applied"`
	SCIMGroupRemovalKeptSecondMember     bool               `json:"scim_group_removal_kept_second_membership"`
	EventLatencySeconds                  map[string]float64 `json:"event_latency_seconds"`
	FullSyncLastStatus                   string             `json:"full_sync_last_status"`
	FullSyncLastSuccessfulSyncPresent    bool               `json:"full_sync_last_successful_sync_present"`
	OIDCSubjectIsNotEmail                bool               `json:"oidc_subject_is_not_email"`
	HealthFailureSignalObserved          bool               `json:"health_failure_signal_observed"`
	FailureSyncStatus                    string             `json:"failure_sync_status"`
	FailureLastSuccessfulSyncUnchanged   bool               `json:"failure_last_successful_sync_unchanged"`
	FailureErrorLogCount                 int                `json:"failure_error_log_count"`
	FailureNewTaskCount                  int                `json:"failure_new_task_count"`
	FailureTaskSummaries                 []contractTask     `json:"failure_task_summaries"`
	FailureTarget503RequestCount         int                `json:"failure_target_503_request_count"`
	RecoveryFullSyncStatus               string             `json:"recovery_full_sync_status"`
	RecoveryEventRetryReconciledUser     bool               `json:"recovery_event_retry_reconciled_user"`
	RecoveryFullSyncRepairedFixtureDrift bool               `json:"recovery_full_sync_repaired_fixture_drift"`
	RecoveryFullSyncUserReadObserved     bool               `json:"recovery_full_sync_user_read_observed"`
	RecoveryFullSyncUserUpdateCount      int                `json:"recovery_full_sync_user_update_count"`
	SCIMUserCountSeen                    int                `json:"scim_user_count_seen"`
	SCIMDuplicateGroupResourceCount      int                `json:"scim_duplicate_group_resource_count"`
}

type contractTask struct {
	Description   string `json:"description"`
	State         string `json:"state"`
	Status        string `json:"status"`
	ErrorLogCount int    `json:"error_log_count"`
}

func setupAuthentikFixture(t *testing.T) {
	t.Helper()
	fixture.secrets = nil
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate Authentik integration fixture")
	}
	fixture.packageDir = filepath.Dir(sourceFile)
	fixture.compose = filepath.Join(fixture.packageDir, "compose.yml")

	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal("generate isolated Authentik fixture name")
	}
	fixture.project = "pr-authentik-" + hex.EncodeToString(suffix[:])

	root, err := os.MkdirTemp("/tmp/opencode", "private-registry-authentik-")
	if err != nil {
		t.Fatal("create private Authentik fixture directory")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal("restrict Authentik fixture directory")
		_ = os.Remove(root)
		return
	}
	fixture.envFile = filepath.Join(root, ".env")
	if err := writeFixtureEnvironment(fixture.envFile); err != nil {
		_ = os.Remove(fixture.envFile)
		_ = os.Remove(root)
		t.Fatal("write private Authentik fixture environment")
	}
	t.Cleanup(func() {
		if err := os.Remove(fixture.envFile); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove private Authentik fixture environment: %v", err)
		}
		if err := os.Remove(root); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove owned Authentik fixture directory: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	_, startErr := runCompose(ctx, "up", "-d")
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 60*time.Second)
		defer stop()
		if _, err := runCompose(cleanup, "down", "--remove-orphans"); err != nil {
			t.Errorf("remove owned Authentik fixture containers: %v", err)
		}
	})
	if startErr != nil {
		t.Fatal("start bounded Authentik fixture; run make setup-authentik")
	}

	fixture.serverID, err = composeContainerID(ctx, "server")
	if err != nil {
		t.Fatal("identify owned Authentik server container")
	}
	fixture.workerID, err = composeContainerID(ctx, "worker")
	if err != nil {
		t.Fatal("identify owned Authentik worker container")
	}
	for _, containerID := range []string{fixture.serverID, fixture.workerID} {
		image, inspectErr := runDocker(ctx, "inspect", "--format", "{{.Config.Image}}", containerID)
		if inspectErr != nil || strings.TrimSpace(string(image)) != authentikImage {
			t.Fatal("verify pinned Authentik container image")
		}
	}
	if err := waitForAuthentik(ctx, fixture.serverID); err != nil {
		t.Fatal("wait for isolated Authentik and PostgreSQL migrations")
	}
	if _, err := runDocker(ctx, "cp", filepath.Join(fixture.packageDir, "scim_target.py"), fixture.serverID+":/tmp/private-registry-scim-target.py"); err != nil {
		t.Fatal("copy owned SCIM target fixture")
	}
	if _, err := runDocker(ctx, "cp", filepath.Join(fixture.packageDir, "contract_probe.py"), fixture.serverID+":/tmp/private-registry-contract-probe.py"); err != nil {
		t.Fatal("copy owned Authentik contract probe")
	}
	if _, err := runDocker(ctx, "exec", "--detach", fixture.serverID, "python", "/tmp/private-registry-scim-target.py"); err != nil {
		t.Fatal("start isolated SCIM target fixture")
	}
	if err := waitForSCIMTarget(ctx, fixture.serverID); err != nil {
		t.Fatal("wait for isolated SCIM target fixture")
	}
}

func writeFixtureEnvironment(path string) error {
	values := []struct {
		name  string
		bytes int
	}{
		{name: "AUTHENTIK_TEST_POSTGRES_PASSWORD", bytes: 24},
		{name: "AUTHENTIK_TEST_SECRET_KEY", bytes: 32},
		{name: "AUTHENTIK_TEST_BOOTSTRAP_TOKEN", bytes: 32},
		{name: "AUTHENTIK_TEST_BOOTSTRAP_PASSWORD", bytes: 24},
		{name: "PRIVATE_REGISTRY_SCIM_FIXTURE_TOKEN", bytes: 32},
	}
	var contents strings.Builder
	for _, item := range values {
		value, err := randomHex(item.bytes)
		if err != nil {
			return err
		}
		fixture.secrets = append(fixture.secrets, value)
		contents.WriteString(item.name)
		contents.WriteByte('=')
		contents.WriteString(value)
		contents.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(contents.String()), 0o600)
}

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func composeContainerID(ctx context.Context, service string) (string, error) {
	output, err := runCompose(ctx, "ps", "-q", service)
	if err != nil {
		return "", err
	}
	containerID := strings.TrimSpace(string(output))
	if len(containerID) != 64 {
		return "", fmt.Errorf("unexpected container id length for service %s", service)
	}
	if _, err := hex.DecodeString(containerID); err != nil {
		return "", fmt.Errorf("invalid container id for service %s", service)
	}
	return containerID, nil
}

func waitForAuthentik(ctx context.Context, containerID string) error {
	for {
		_, err := runDocker(ctx, "exec", containerID, "python", "-c",
			"import os, urllib.request; request=urllib.request.Request('http://127.0.0.1:9000/api/v3/core/users/me/', headers={'Authorization': 'Bearer ' + os.environ['AUTHENTIK_BOOTSTRAP_TOKEN']}); urllib.request.urlopen(request, timeout=2)")
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func waitForSCIMTarget(ctx context.Context, containerID string) error {
	for {
		_, err := runDocker(ctx, "exec", containerID, "python", "-c",
			"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=2)")
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func runCompose(ctx context.Context, args ...string) ([]byte, error) {
	composeArgs := []string{
		"compose",
		"--env-file", fixture.envFile,
		"--file", fixture.compose,
		"--project-name", fixture.project,
	}
	composeArgs = append(composeArgs, args...)
	return runDocker(ctx, composeArgs...)
}

func runDocker(ctx context.Context, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	command.Dir = fixture.packageDir
	return command.CombinedOutput()
}

func TestAuthentikOIDCAndSCIMContract(t *testing.T) {
	setupAuthentikFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	output, err := runDocker(ctx, "exec", fixture.serverID, "python", "/tmp/private-registry-contract-probe.py")
	if err != nil {
		message := string(output)
		for _, secret := range fixture.secrets {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
		t.Fatalf("Authentik contract probe failed: %v\n%s", err, message)
	}
	var report contractReport
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatalf("decode Authentik contract report: %v\n%s", err, output)
	}
	if report.AuthentikVersion != "2026.8.3" {
		t.Fatalf("unexpected Authentik version: %q", report.AuthentikVersion)
	}
	if report.OIDCAlgorithm != "RS256" || !report.OIDCSignatureVerified || !report.OIDCSubjectMatchesSCIMExternalID || !report.OIDCSubjectIsNotEmail {
		t.Fatalf("OIDC issuer, signature, or stable identity contract failed: %+v", report)
	}
	if !report.SCIMDeactivationApplied || !report.SCIMGroupRemovalKeptSecondMember {
		t.Fatalf("SCIM deactivation or group membership contract failed: %+v", report)
	}
	if report.FullSyncLastStatus != "info" || !report.FullSyncLastSuccessfulSyncPresent {
		t.Fatalf("Authentik did not report a successful full sync: %+v", report)
	}
	if report.FailureTarget503RequestCount == 0 || !report.FailureLastSuccessfulSyncUnchanged {
		t.Fatalf("controlled SCIM outage did not preserve the previous successful sync marker: %+v", report)
	}
	queuedFailureTask := false
	for _, task := range report.FailureTaskSummaries {
		if task.State == "queued" || task.Status == "queued" {
			queuedFailureTask = true
			break
		}
	}
	if report.HealthFailureSignalObserved || report.FailureSyncStatus != "info" || report.FailureErrorLogCount != 0 || !queuedFailureTask {
		t.Fatalf("pinned Authentik outage behavior changed; review the health contract and update the spike evidence: %+v", report)
	}
	if report.RecoveryFullSyncStatus != "info" {
		t.Fatalf("SCIM sync did not recover after the target outage ended: %+v", report)
	}
	if !report.RecoveryFullSyncUserReadObserved || report.RecoveryFullSyncUserUpdateCount > 1 ||
		(report.RecoveryFullSyncRepairedFixtureDrift && report.RecoveryFullSyncUserUpdateCount == 0) {
		t.Fatalf("unexpected Authentik full-sync observation; review reconciliation evidence: %+v", report)
	}
	if len(report.EventLatencySeconds) == 0 {
		t.Fatal("SCIM event delivery latency was not measured")
	}
	t.Logf("Authentik 2026.8.3 contract report: %+v", report)
}
