//go:build linux && integration

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/pub"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
)

func TestPubReadProtocolRealDartClient(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var owner string
	if err := fixture.db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "pub-real-client", "Pub client")
	if err != nil {
		t.Fatal(err)
	}
	repository := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_repositories (repository_id, workspace_id, slug, display_name, created_by, created_at, updated_at, format) VALUES (?, ?, 'pub', 'Pub', ?, 'now', 'now', 'pub')`, repository, workspace.ID, owner); err != nil {
		t.Fatal(err)
	}
	for _, role := range []repositories.GrantRole{repositories.GrantReader, repositories.GrantPublisher} {
		if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repository, owner, role); err != nil {
			t.Fatal(err)
		}
	}
	readToken, err := fixture.repositoryService.IssuePersonalReadToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	writeToken, err := fixture.repositoryService.IssuePubWriteToken(ctx, owner, workspace.ID, repository, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	stage := filepath.Join(root, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	objects, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	reservations, err := pub.NewReservationService(fixture.db, fixture.repositoryService, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := pub.NewReceiptService(fixture.db, fixture.repositoryService, config.SQLite, objects, pub.ReceiptOptions{StagingDirectory: stage, MaxConcurrent: 2, Limits: pub.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("name: registry_fixture_leaf\nversion: 1.0.0\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\n")
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	w := tar.NewWriter(gz)
	for _, item := range []struct {
		name    string
		content []byte
	}{{"pubspec.yaml", manifest}, {"lib/registry_fixture_leaf.dart", []byte("String value() => 'synthetic';\n")}} {
		if err := w.WriteHeader(&tar.Header{Name: item.name, Mode: 0o600, Size: int64(len(item.content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(item.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	digest, metadata := sha256.Sum256(archive.Bytes()), sha256.Sum256(manifest)
	request := pub.ReservationRequest{Name: "registry_fixture_leaf", Version: "1.0.0", TarballSHA256: hex.EncodeToString(digest[:]), TarballSize: int64(archive.Len()), MetadataSHA256: hex.EncodeToString(metadata[:])}
	reservation, err := reservations.Reserve(ctx, writeToken.Bearer, workspace.ID, repository, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.Receive(ctx, writeToken.Bearer, workspace.ID, repository, reservation.ID, pub.ReceiptInput{Name: request.Name, Version: request.Version, Manifest: manifest, Size: request.TarballSize}, bytes.NewReader(archive.Bytes())); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.PublishReceipt(ctx, writeToken.Bearer, workspace.ID, repository, reservation.ID); err != nil {
		t.Fatal(err)
	}
	var handler http.Handler
	var pathsMu sync.Mutex
	var paths []string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		pathsMu.Lock()
		paths = append(paths, request.Method+" "+request.URL.Path)
		pathsMu.Unlock()
		handler.ServeHTTP(response, request)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	handler, err = NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: server.URL, AssetOrigin: "https://assets.example", PubReservations: reservations, PubReceipts: receipts, PubReadProtocol: true, PubWriteProtocol: &PubWriteProtocolConfig{StagingDirectory: stage, MaxArchiveBytes: 1 << 20, MaxConcurrent: 2, Limits: pub.ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 20, MaxManifestBytes: 4096}}})
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	registry := server.URL + "/pub/" + workspace.ID + "/" + repository
	parentManifest := []byte(fmt.Sprintf("name: registry_fixture_parent\nversion: 1.0.0\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n  registry_fixture_leaf:\n    hosted:\n      name: registry_fixture_leaf\n      url: %s\n    version: ^1.0.0\n", registry))
	var parentArchive bytes.Buffer
	parentGzip := gzip.NewWriter(&parentArchive)
	parentTar := tar.NewWriter(parentGzip)
	for _, item := range []struct {
		name    string
		content []byte
	}{{"pubspec.yaml", parentManifest}, {"lib/registry_fixture_parent.dart", []byte("import 'package:registry_fixture_leaf/registry_fixture_leaf.dart';\nString parent() => value();\n")}} {
		if err := parentTar.WriteHeader(&tar.Header{Name: item.name, Mode: 0o600, Size: int64(len(item.content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := parentTar.Write(item.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := parentTar.Close(); err != nil {
		t.Fatal(err)
	}
	if err := parentGzip.Close(); err != nil {
		t.Fatal(err)
	}
	parentDigest, parentMetadata := sha256.Sum256(parentArchive.Bytes()), sha256.Sum256(parentManifest)
	parentRequest := pub.ReservationRequest{Name: "registry_fixture_parent", Version: "1.0.0", TarballSHA256: hex.EncodeToString(parentDigest[:]), TarballSize: int64(parentArchive.Len()), MetadataSHA256: hex.EncodeToString(parentMetadata[:])}
	parentReservation, err := reservations.Reserve(ctx, writeToken.Bearer, workspace.ID, repository, parentRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.Receive(ctx, writeToken.Bearer, workspace.ID, repository, parentReservation.ID, pub.ReceiptInput{Name: parentRequest.Name, Version: parentRequest.Version, Manifest: parentManifest, Size: parentRequest.TarballSize}, bytes.NewReader(parentArchive.Bytes())); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.PublishReceipt(ctx, writeToken.Bearer, workspace.ID, repository, parentReservation.ID); err != nil {
		t.Fatal(err)
	}
	consumer := filepath.Join(root, "consumer")
	if err := os.Mkdir(consumer, 0o700); err != nil {
		t.Fatal(err)
	}
	consumerManifest := fmt.Sprintf("name: synthetic_consumer\npublish_to: none\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n  registry_fixture_parent:\n    hosted:\n      name: registry_fixture_parent\n      url: %s\n    version: ^1.0.0\n", registry)
	if err := os.WriteFile(filepath.Join(consumer, "pubspec.yaml"), []byte(consumerManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	configHome := filepath.Join(root, "config")
	for _, dir := range []string{filepath.Join(root, "home"), configHome, filepath.Join(root, "cache")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dart := os.Getenv("PUB_TEST_DART_BIN")
	if dart == "" {
		dart, err = exec.LookPath("dart")
		if err != nil {
			t.Fatal(err)
		}
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(root, "home"), "XDG_CONFIG_HOME=" + configHome, "PUB_CACHE=" + filepath.Join(root, "cache"), "PUB_ENVIRONMENT=bot", "CI=true", "SSL_CERT_FILE=" + caPath, "PUB_FIXTURE_TOKEN=" + readToken.Bearer, "HTTP_PROXY=http://127.0.0.1:9", "HTTPS_PROXY=http://127.0.0.1:9", "ALL_PROXY=http://127.0.0.1:9", "http_proxy=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9", "all_proxy=http://127.0.0.1:9", "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost"}
	run := func(args ...string) ([]byte, error) {
		runtime := filepath.Join(filepath.Dir(dart), "dartaotruntime")
		snapshot := filepath.Join(filepath.Dir(dart), "snapshots", "dartdev_aot.dart.snapshot")
		arguments := append([]string{"--root-certs-file=" + caPath, snapshot}, args...)
		cmd := exec.CommandContext(ctx, runtime, arguments...)
		cmd.Dir = consumer
		cmd.Env = env
		return cmd.CombinedOutput()
	}
	output, _ := run("pub", "get")
	if !strings.Contains(string(output), "authentication failed") {
		t.Fatalf("Dart Pub did not report missing authentication: %s", strings.ReplaceAll(string(output), readToken.Bearer, "[redacted]"))
	}
	if _, err := os.Stat(filepath.Join(consumer, "pubspec.lock")); !os.IsNotExist(err) {
		t.Fatalf("Dart Pub created a lockfile without authorization: %v", err)
	}
	if output, err := run("pub", "token", "add", "--env-var=PUB_FIXTURE_TOKEN", registry); err != nil {
		t.Fatalf("Dart Pub token setup failed: %v output=%s", err, strings.ReplaceAll(string(output), readToken.Bearer, "[redacted]"))
	}
	if output, err := run("pub", "get"); err != nil {
		t.Fatalf("Dart Pub get failed: %v output=%s", err, strings.ReplaceAll(string(output), readToken.Bearer, "[redacted]"))
	}
	lock, err := os.ReadFile(filepath.Join(consumer, "pubspec.lock"))
	if err != nil || !strings.Contains(string(lock), "registry_fixture_leaf") || !strings.Contains(string(lock), "registry_fixture_parent") || !strings.Contains(string(lock), "1.0.0") {
		t.Fatalf("Dart Pub did not create lockfile: %v", err)
	}
	publisher := filepath.Join(root, "publisher")
	if err := os.MkdirAll(filepath.Join(publisher, "lib"), 0o700); err != nil {
		t.Fatal(err)
	}
	pubspec := fmt.Sprintf("name: registry_native_fixture\nversion: 1.0.0\ndescription: Synthetic fixture package for local testing.\npublish_to: %s\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\n", registry)
	if err := os.WriteFile(filepath.Join(publisher, "pubspec.yaml"), []byte(pubspec), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(publisher, "lib", "registry_native_fixture.dart"), []byte("String value() => 'fixture';\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(publisher, "LICENSE"), []byte("Synthetic test fixture; not for distribution.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	publisherConfig := filepath.Join(root, "publisher-config")
	if err := os.Mkdir(publisherConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	publisherEnv := append([]string(nil), env...)
	for i, value := range publisherEnv {
		if strings.HasPrefix(value, "XDG_CONFIG_HOME=") {
			publisherEnv[i] = "XDG_CONFIG_HOME=" + publisherConfig
		}
		if strings.HasPrefix(value, "PUB_FIXTURE_TOKEN=") {
			publisherEnv[i] = "PUB_FIXTURE_TOKEN=" + writeToken.Bearer
		}
	}
	runPublisher := func(args ...string) ([]byte, error) {
		runtime := filepath.Join(filepath.Dir(dart), "dartaotruntime")
		snapshot := filepath.Join(filepath.Dir(dart), "snapshots", "dartdev_aot.dart.snapshot")
		arguments := append([]string{"--root-certs-file=" + caPath, snapshot}, args...)
		cmd := exec.CommandContext(ctx, runtime, arguments...)
		cmd.Dir = publisher
		cmd.Env = publisherEnv
		return cmd.CombinedOutput()
	}
	if output, err := runPublisher("pub", "token", "add", "--env-var=PUB_FIXTURE_TOKEN", registry); err != nil {
		t.Fatalf("Dart publisher token setup failed: %v output=%s", err, strings.ReplaceAll(string(output), writeToken.Bearer, "[redacted]"))
	}
	output, err = runPublisher("pub", "publish", "--force")
	var published int
	queryErr := fixture.db.QueryRowContext(ctx, `SELECT count(*) FROM registry_pub_packages WHERE repository_id = ? AND name = 'registry_native_fixture'`, repository).Scan(&published)
	if err != nil || queryErr != nil || published != 1 {
		pathsMu.Lock()
		observed := append([]string(nil), paths...)
		pathsMu.Unlock()
		t.Fatalf("Dart native publication failed: err=%v published=%d query=%v paths=%v output=%s", err, published, queryErr, observed, strings.ReplaceAll(string(output), writeToken.Bearer, "[redacted]"))
	}
	if _, err := fixture.repositoryService.SetPubReviewPolicy(ctx, owner, workspace.ID, repository, 0, true); err != nil {
		t.Fatal(err)
	}
	reviewedSpec := strings.Replace(pubspec, "registry_native_fixture", "registry_review_fixture", 1)
	if err := os.WriteFile(filepath.Join(publisher, "pubspec.yaml"), []byte(reviewedSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	output, _ = runPublisher("pub", "publish", "--force")
	if !strings.Contains(string(output), "review") {
		t.Fatalf("Dart did not report pending review: %s", strings.ReplaceAll(string(output), writeToken.Bearer, "[redacted]"))
	}
	if err := fixture.db.QueryRowContext(ctx, `SELECT count(*) FROM registry_pub_packages WHERE repository_id = ? AND name = 'registry_review_fixture'`, repository).Scan(&published); err != nil || published != 0 {
		t.Fatalf("pending Dart publication was published: count=%d err=%v", published, err)
	}
	var reviewReservation string
	if err := fixture.db.QueryRowContext(ctx, `SELECT reservation_id FROM registry_pub_reservations WHERE repository_id = ? AND name = 'registry_review_fixture' AND status = 'uploaded'`, repository).Scan(&reviewReservation); err != nil {
		t.Fatal(err)
	}
	reviewer := uuid.NewString()
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_users (user_id, display_name, created_at, updated_at) VALUES (?, 'Synthetic reviewer', 'now', 'now')`, reviewer); err != nil {
		t.Fatal(err)
	}
	if err := fixture.workspaceService.SetMembershipRole(ctx, owner, workspace.ID, reviewer, workspaces.RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.repositoryService.GrantPubReviewer(ctx, owner, workspace.ID, repository, reviewer); err != nil {
		t.Fatal(err)
	}
	if _, err := reservations.DecideReview(ctx, reviewer, workspace.ID, repository, reviewReservation, "approved", ""); err != nil {
		t.Fatal(err)
	}
	output, err = runPublisher("pub", "publish", "--force")
	queryErr = fixture.db.QueryRowContext(ctx, `SELECT count(*) FROM registry_pub_packages WHERE repository_id = ? AND name = 'registry_review_fixture'`, repository).Scan(&published)
	if err != nil || queryErr != nil || published != 1 {
		t.Fatalf("approved Dart publication retry failed: err=%v count=%d query=%v output=%s", err, published, queryErr, strings.ReplaceAll(string(output), writeToken.Bearer, "[redacted]"))
	}
}
