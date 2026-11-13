//go:build linux && integration

package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/cargo"
	"private-registry/internal/config"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
)

type syntheticCorruptCargoStore struct {
	storage.Driver
	corrupt atomic.Bool
}

func (s *syntheticCorruptCargoStore) Open(ctx context.Context, key storage.ObjectKey) (io.ReadCloser, storage.ObjectInfo, error) {
	reader, info, err := s.Driver.Open(ctx, key)
	if err != nil || !s.corrupt.Load() {
		return reader, info, err
	}
	content, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(content) == 0 {
		return nil, storage.ObjectInfo{}, fmt.Errorf("synthetic corruption fixture could not read object")
	}
	content[len(content)-1] ^= 1
	return io.NopCloser(bytes.NewReader(content)), info, nil
}

func TestCargoProtocolRealClientReviewedPublication(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var owner string
	if err := fixture.db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	reviewer := seedHTTPUser(t, fixture, "cargo.client.reviewer")
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "cargo-client", "Cargo client")
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.workspaceService.SetMembershipRole(ctx, owner, workspace.ID, reviewer, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format, review_required) VALUES (?, ?, 'cargo', 'Cargo', ?, 'now', 'now', 'cargo', 1)`, repository, workspace.ID, owner); err != nil {
		t.Fatal(err)
	}
	for _, role := range []repositories.GrantRole{repositories.GrantReader, repositories.GrantPublisher} {
		if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repository, owner, role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.repositoryService.GrantCargoReviewer(ctx, owner, workspace.ID, repository, reviewer); err != nil {
		t.Fatal(err)
	}
	writeToken, err := fixture.repositoryService.IssueCargoWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	readToken, err := fixture.repositoryService.IssuePersonalReadToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	objects, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	corruptStore := &syntheticCorruptCargoStore{Driver: objects}
	reservations, err := cargo.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	var handler http.Handler
	var downloads atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/download") {
			downloads.Add(1)
		}
		handler.ServeHTTP(response, request)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	base := server.URL + "/cargo/" + workspace.ID + "/" + repository
	receipts, err := cargo.NewReceiptService(fixture.db, fixture.repositoryService, config.SQLite, corruptStore, cargo.ReceiptOptions{StagingDirectory: staging, Limits: cargo.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 8 << 20, MaxFiles: 100, MaxManifestBytes: 1 << 20}, MaxConcurrent: 2, CurrentIndex: "sparse+" + base + "/index/", DefaultIndex: "https://github.com/rust-lang/crates.io-index"})
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: server.URL, AssetOrigin: "https://assets.example", CargoReservations: reservations, CargoReceipts: receipts, CargoProtocol: &CargoProtocolConfig{StagingDirectory: staging, MaxArchiveBytes: 1 << 20, MaxConcurrent: 2}})
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(root, "test-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cargoHome := filepath.Join(root, "cargo-home")
	if err := os.Mkdir(cargoHome, 0o700); err != nil {
		t.Fatal(err)
	}
	providerPath := filepath.Join(root, "credential-provider.py")
	provider := `#!/usr/bin/python3
import json, os, sys
print(json.dumps({"v": [1]}), flush=True)
for line in sys.stdin:
    request = json.loads(line)
    operation = request.get("operation")
    with open(os.environ["TEST_CARGO_OPERATIONS"], "a", encoding="utf-8") as log:
        log.write(str(operation) + "\n")
    if request.get("v") != 1 or request.get("kind") != "get" or request.get("registry", {}).get("index-url") != os.environ["TEST_CARGO_INDEX"] or operation not in ("read", "publish", "yank", "unyank"):
        print(json.dumps({"Err": {"kind": "operation-not-supported"}}), flush=True)
        continue
    token = os.environ["TEST_CARGO_READ_TOKEN"] if operation == "read" else os.environ["TEST_CARGO_WRITE_TOKEN"]
    print(json.dumps({"Ok": {"kind": "get", "token": token, "cache": "never", "operation_independent": False}}), flush=True)
`
	if err := os.WriteFile(providerPath, []byte(provider), 0o700); err != nil {
		t.Fatal(err)
	}
	configuration := fmt.Sprintf("[credential-alias]\nfixture = [%q]\n[registries.private]\nindex = %q\ncredential-provider = \"fixture\"\n", providerPath, "sparse+"+base+"/index/")
	if err := os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "crate")
	if err := os.MkdirAll(filepath.Join(project, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "Cargo.toml"), []byte("[package]\nname = \"private_real_fixture\"\nversion = \"1.0.0\"\nedition = \"2021\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "src", "lib.rs"), []byte("pub fn value() -> u8 { 7 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sysrootCmd := exec.CommandContext(ctx, "rustup", "run", "1.99.0-x86_64-unknown-linux-gnu", "rustc", "--print", "sysroot")
	sysroot, err := sysrootCmd.Output()
	if err != nil {
		t.Fatal("Rust integration toolchain unavailable")
	}
	bin := filepath.Join(strings.TrimSpace(string(sysroot)), "bin")
	run := func(args ...string) (string, error) {
		t.Helper()
		command := exec.CommandContext(ctx, filepath.Join(bin, "cargo"), args...)
		command.Dir = root
		command.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + root, "CARGO_HOME=" + cargoHome, "CARGO_TARGET_DIR=" + filepath.Join(root, "target"), "TEST_CARGO_INDEX=sparse+" + base + "/index/", "TEST_CARGO_OPERATIONS=" + filepath.Join(root, "provider-operations"), "TEST_CARGO_READ_TOKEN=" + readToken.Bearer, "TEST_CARGO_WRITE_TOKEN=" + writeToken.Bearer, "CARGO_HTTP_CAINFO=" + caPath, "CARGO_HTTP_TIMEOUT=20", "CARGO_HTTP_MULTIPLEXING=false", "CARGO_NET_RETRY=0", "CARGO_TERM_COLOR=never", "HTTP_PROXY=http://127.0.0.1:9", "HTTPS_PROXY=http://127.0.0.1:9", "http_proxy=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9", "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost"}
		output, err := command.CombinedOutput()
		safe := strings.ReplaceAll(string(output), writeToken.Bearer, "[redacted]")
		safe = strings.ReplaceAll(safe, readToken.Bearer, "[redacted]")
		return safe, err
	}
	args := []string{"publish", "--no-verify", "--allow-dirty", "--registry", "private", "--manifest-path", filepath.Join(project, "Cargo.toml")}
	output, err := run(args...)
	if err == nil || !strings.Contains(output, "human review required") {
		t.Fatalf("Cargo did not report pending review: %v\n%s", err, output)
	}
	var reservationID string
	if err := fixture.db.QueryRowContext(ctx, `SELECT reservation_id FROM registry_cargo_reservations WHERE repository_id = ? AND name = 'private_real_fixture' AND status = 'uploaded'`, repository).Scan(&reservationID); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace.ID, repository, reservationID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	if output, err := run(args...); err != nil {
		t.Fatalf("Cargo approved retry failed: %v\n%s", err, output)
	}
	parent := filepath.Join(root, "parent")
	if err := os.MkdirAll(filepath.Join(parent, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	parentManifest := "[package]\nname = \"private_real_parent\"\nversion = \"1.0.0\"\nedition = \"2021\"\n[dependencies]\nprivate_real_fixture = { version = \"=1.0.0\", registry = \"private\" }\n"
	if err := os.WriteFile(filepath.Join(parent, "Cargo.toml"), []byte(parentManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "src", "lib.rs"), []byte("pub fn value() -> u8 { private_real_fixture::value() }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parentArgs := []string{"publish", "--no-verify", "--allow-dirty", "--registry", "private", "--manifest-path", filepath.Join(parent, "Cargo.toml")}
	if output, err := run(parentArgs...); err == nil || !strings.Contains(output, "human review required") {
		t.Fatalf("Cargo parent did not report pending review: %v\n%s", err, output)
	}
	if err := fixture.db.QueryRowContext(ctx, `SELECT reservation_id FROM registry_cargo_reservations WHERE repository_id = ? AND name = 'private_real_parent' AND status = 'uploaded'`, repository).Scan(&reservationID); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace.ID, repository, reservationID, "approved", ""); err != nil {
		t.Fatal(err)
	}
	if output, err := run(parentArgs...); err != nil {
		t.Fatalf("Cargo approved parent retry failed: %v\n%s", err, output)
	}
	consumer := filepath.Join(root, "consumer")
	if err := os.MkdirAll(filepath.Join(consumer, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	consumerManifest := "[package]\nname = \"fixture_consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nprivate_real_parent = { version = \"=1.0.0\", registry = \"private\" }\n"
	if err := os.WriteFile(filepath.Join(consumer, "Cargo.toml"), []byte(consumerManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(consumer, "src", "main.rs"), []byte("fn main() { assert_eq!(private_real_parent::value(), 7); }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := run("run", "--manifest-path", filepath.Join(consumer, "Cargo.toml")); err != nil {
		t.Fatalf("Cargo consumption failed: %v\n%s", err, output)
	}
	if output, err := run("yank", "--registry", "private", "--vers", "1.0.0", "private_real_fixture"); err != nil {
		operations, _ := os.ReadFile(filepath.Join(root, "provider-operations"))
		t.Fatalf("Cargo yank failed: %v\n%s\noperations=%s", err, output, operations)
	}
	cargoHome = filepath.Join(root, "fresh-cargo-home")
	if err := os.Mkdir(cargoHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	beforeFreshDownload := downloads.Load()
	if output, err := run("run", "--locked", "--manifest-path", filepath.Join(consumer, "Cargo.toml")); err != nil {
		t.Fatalf("Cargo lockfile failed after yank with fresh Cargo home: %v\n%s", err, output)
	}
	if downloads.Load() <= beforeFreshDownload {
		t.Fatal("Cargo did not fetch the yanked archive with fresh Cargo home")
	}
	freshConsumer := filepath.Join(root, "new-consumer")
	if err := os.MkdirAll(filepath.Join(freshConsumer, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(freshConsumer, "Cargo.toml"), []byte(strings.Replace(consumerManifest, "fixture_consumer", "fixture_new_consumer", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(freshConsumer, "src", "main.rs"), []byte("fn main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := run("generate-lockfile", "--manifest-path", filepath.Join(freshConsumer, "Cargo.toml")); err == nil || !strings.Contains(output, "yanked") {
		t.Fatalf("Cargo resolved a yanked version without an existing lockfile: %v\n%s", err, output)
	}
	if output, err := run("yank", "--undo", "--registry", "private", "--vers", "1.0.0", "private_real_fixture"); err != nil {
		t.Fatalf("Cargo unyank failed: %v\n%s", err, output)
	}
	if output, err := run("generate-lockfile", "--manifest-path", filepath.Join(freshConsumer, "Cargo.toml")); err != nil {
		t.Fatalf("Cargo did not resolve the unyanked version: %v\n%s", err, output)
	}
	cargoHome = filepath.Join(root, "corrupt-cargo-home")
	if err := os.Mkdir(cargoHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	corruptStore.corrupt.Store(true)
	if output, err := run("run", "--locked", "--manifest-path", filepath.Join(freshConsumer, "Cargo.toml")); err == nil || !strings.Contains(strings.ToLower(output), "checksum") {
		t.Fatalf("Cargo did not reject corrupted published archive: %v\n%s", err, output)
	}
}
