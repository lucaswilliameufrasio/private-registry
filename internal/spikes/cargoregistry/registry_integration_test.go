//go:build integration

package cargoregistry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"private-registry/internal/cargo"
)

const (
	cargoRegistryName = "private"
	rustToolchain     = "1.99.0-x86_64-unknown-linux-gnu"
	leafCrateName     = "registry_fixture_leaf"
	parentCrateName   = "registry_fixture_parent"
	helperCrateName   = "registry_fixture_helper"
	crateVersion      = "1.0.0"
	maxUploadBytes    = 8 << 20
)

type cargoDependency struct {
	Name               string   `json:"name"`
	VersionReq         string   `json:"version_req"`
	Features           []string `json:"features"`
	Optional           bool     `json:"optional"`
	DefaultFeatures    bool     `json:"default_features"`
	Target             *string  `json:"target"`
	Kind               string   `json:"kind"`
	Registry           *string  `json:"registry"`
	ExplicitNameInTOML *string  `json:"explicit_name_in_toml"`
}

type cargoPublishMetadata struct {
	Name         string              `json:"name"`
	Version      string              `json:"vers"`
	Dependencies []cargoDependency   `json:"deps"`
	Features     map[string][]string `json:"features"`
	Links        *string             `json:"links"`
	RustVersion  *string             `json:"rust_version"`
}

type cargoIndexDependency struct {
	Name            string   `json:"name"`
	Requirement     string   `json:"req"`
	Features        []string `json:"features"`
	Optional        bool     `json:"optional"`
	DefaultFeatures bool     `json:"default_features"`
	Target          *string  `json:"target"`
	Kind            string   `json:"kind"`
	Registry        *string  `json:"registry"`
	Package         *string  `json:"package"`
}

type cargoIndexEntry struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"vers"`
	Dependencies []cargoIndexDependency `json:"deps"`
	Checksum     string                 `json:"cksum"`
	Features     map[string][]string    `json:"features"`
	Yanked       bool                   `json:"yanked"`
	Links        *string                `json:"links"`
	RustVersion  *string                `json:"rust_version"`
}

type publishedCrate struct {
	metadata cargoPublishMetadata
	entry    cargoIndexEntry
	archive  []byte
}

type registryFixture struct {
	URL                string
	Token              string
	mu                 sync.Mutex
	crates             map[string]*publishedCrate
	indexRequests      int
	downloadRequests   int
	publishRequests    int
	yankRequests       int
	configRequests     int
	unauthorizedPaths  []string
	unexpectedRequests []string
	requireReview      bool
}

func TestCargoPublishesBuildsAndYanksAuthenticatedPrivateCrates(t *testing.T) {
	cargoVersion := runCommandVersion(t, "rustup", "run", rustToolchain, "cargo", "--version")
	if !strings.HasPrefix(cargoVersion, "cargo 1.99.0 ") {
		t.Fatalf("unsupported Cargo integration baseline %q; expected cargo 1.99.0", cargoVersion)
	}
	rustcVersion := runCommandVersion(t, "rustup", "run", rustToolchain, "rustc", "--version")
	if !strings.HasPrefix(rustcVersion, "rustc 1.99.0 ") {
		t.Fatalf("unsupported Rust integration baseline %q; expected rustc 1.99.0", rustcVersion)
	}

	root := t.TempDir()
	registry := startRegistryFixture(t)
	cargoHome := filepath.Join(root, "cargo-home")
	writeCargoHome(t, cargoHome, registry.URL)
	environment := cargoEnvironment(t, root, cargoHome, registry.Token)

	leafProject := writeCargoPackage(t, root, leafCrateName, crateVersion, `rust-version = "1.80"

[lib]
path = "src/lib.rs"

[features]
default = ["leaf-fast"]
leaf-fast = []
`, `#[cfg(feature = "leaf-fast")]
pub fn value() -> &'static str { "leaf-fast-value" }

#[cfg(not(feature = "leaf-fast"))]
pub fn value() -> &'static str { "leaf-basic-value" }
`)
	helperProject := writeCargoPackage(t, root, helperCrateName, crateVersion, "links = \"fixture_helper\"\n", "pub fn helper() {}\n")
	if err := os.WriteFile(filepath.Join(helperProject, "build.rs"), []byte("fn main() {}\n"), 0o600); err != nil {
		t.Fatal("write synthetic build script:", err)
	}
	parentProject := writeCargoPackage(t, root, parentCrateName, crateVersion, `[dependencies]
leaf_alias = { package = "registry_fixture_leaf", version = "1.0.0", registry = "private", optional = true }

[target.'cfg(windows)'.build-dependencies]
registry_fixture_helper = { version = "1.0.0", registry = "private" }

[features]
default = ["fast"]
fast = ["dep:leaf_alias", "leaf_alias?/leaf-fast"]
`, `#[cfg(feature = "fast")]
pub fn value() -> &'static str { leaf_alias::value() }

#[cfg(not(feature = "fast"))]
pub fn value() -> &'static str { "parent-basic-value" }
`)
	runCargo(t, root, environment, "publish", "--allow-dirty", "--registry", cargoRegistryName, "--manifest-path", filepath.Join(leafProject, "Cargo.toml"))
	runCargo(t, root, environment, "publish", "--allow-dirty", "--registry", cargoRegistryName, "--manifest-path", filepath.Join(helperProject, "Cargo.toml"))
	runCargo(t, root, environment, "publish", "--allow-dirty", "--registry", cargoRegistryName, "--manifest-path", filepath.Join(parentProject, "Cargo.toml"))

	consumer := writeCargoConsumer(t, root, "consumer-locked", `registry_fixture_parent = { version = "=1.0.0", registry = "private", features = ["fast"] }
`, `fn main() { println!("{}", registry_fixture_parent::value()); }
`)
	output := runCargo(t, root, environment, "run", "--manifest-path", filepath.Join(consumer, "Cargo.toml"))
	if !strings.HasSuffix(strings.TrimSpace(output), "leaf-fast-value") {
		t.Fatalf("Cargo did not build the private transitive dependency with requested features: %s", output)
	}
	if _, err := os.Stat(filepath.Join(consumer, "Cargo.lock")); err != nil {
		t.Fatalf("Cargo did not create a lockfile: %v", err)
	}

	runCargo(t, root, environment, "yank", "--registry", cargoRegistryName, "--vers", crateVersion, parentCrateName)
	if !registry.isYanked(parentCrateName, crateVersion) {
		t.Fatal("Cargo yank request did not mark the indexed version yanked")
	}
	runCargo(t, root, environment, "build", "--locked", "--manifest-path", filepath.Join(consumer, "Cargo.toml"))

	freshHome := filepath.Join(root, "cargo-home-after-yank")
	writeCargoHome(t, freshHome, registry.URL)
	freshEnvironment := cargoEnvironment(t, root, freshHome, registry.Token)
	lockedCopy := writeCargoConsumer(t, filepath.Join(root, "fresh-locked"), "consumer-locked", `registry_fixture_parent = { version = "=1.0.0", registry = "private", features = ["fast"] }
`, `fn main() { println!("{}", registry_fixture_parent::value()); }
`)
	lockfile, err := os.ReadFile(filepath.Join(consumer, "Cargo.lock"))
	if err != nil {
		t.Fatal("read synthetic lockfile:", err)
	}
	if err := os.WriteFile(filepath.Join(lockedCopy, "Cargo.lock"), lockfile, 0o600); err != nil {
		t.Fatal("write synthetic lockfile:", err)
	}
	runCargo(t, root, freshEnvironment, "build", "--locked", "--manifest-path", filepath.Join(lockedCopy, "Cargo.toml"))
	freshConsumer := writeCargoConsumer(t, root, "consumer-fresh", `registry_fixture_parent = { version = "=1.0.0", registry = "private", features = ["fast"] }
`, `fn main() { println!("{}", registry_fixture_parent::value()); }
`)
	if output, err := runCargoExpectedFailure(t, root, freshEnvironment, "check", "--manifest-path", filepath.Join(freshConsumer, "Cargo.toml")); err == nil {
		t.Fatalf("a fresh Cargo resolution accepted the only yanked private version: %s", output)
	} else if !strings.Contains(strings.ToLower(output), "yanked") {
		t.Fatalf("fresh resolution failed for a reason other than yanked-version policy: %s", output)
	}

	unauthorizedOffset := len(registry.unauthorizedPathsSnapshot())
	invalidHome := filepath.Join(root, "cargo-home-invalid-token")
	writeCargoHome(t, invalidHome, registry.URL)
	invalidToken := "Bearer " + hex.EncodeToString(randomBytes(t, 32))
	invalidEnvironment := cargoEnvironment(t, root, invalidHome, invalidToken)
	invalidConsumer := writeCargoConsumer(t, root, "consumer-invalid-token", `registry_fixture_parent = { version = "=1.0.0", registry = "private" }
`, `fn main() { println!("{}", registry_fixture_parent::value()); }
`)
	if output, err := runCargoExpectedFailure(t, root, invalidEnvironment, "check", "--manifest-path", filepath.Join(invalidConsumer, "Cargo.toml")); err == nil {
		t.Fatalf("Cargo accepted a registry request with an invalid credential: %s", output)
	}
	unauthorizedRequests := registry.unauthorizedPathsSnapshot()
	if len(unauthorizedRequests) != unauthorizedOffset+1 || unauthorizedRequests[len(unauthorizedRequests)-1] != "GET /index/re/gi/registry_fixture_parent" {
		t.Fatalf("invalid Cargo credential did not fail at the protected sparse index: %v", unauthorizedRequests)
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.publishRequests != 3 {
		t.Errorf("Cargo publish requests = %d, want 3", registry.publishRequests)
	}
	if registry.yankRequests != 1 {
		t.Errorf("Cargo yank requests = %d, want 1", registry.yankRequests)
	}
	if registry.indexRequests == 0 || registry.downloadRequests == 0 || registry.configRequests == 0 {
		t.Errorf("expected authenticated index/download and config requests; index=%d download=%d config=%d", registry.indexRequests, registry.downloadRequests, registry.configRequests)
	}
	if len(registry.unauthorizedPaths) != 1 {
		t.Errorf("Cargo protected-route auth failures = %d, want the single intentional invalid-token probe", len(registry.unauthorizedPaths))
	}
	if len(registry.unexpectedRequests) != 0 {
		t.Errorf("Cargo requested unsupported local registry routes: %v", registry.unexpectedRequests)
	}
}

func TestCargoRejectsTamperedCrate(t *testing.T) {
	root := t.TempDir()
	registry := startRegistryFixture(t)
	cargoHome := filepath.Join(root, "cargo-home")
	writeCargoHome(t, cargoHome, registry.URL)
	environment := cargoEnvironment(t, root, cargoHome, registry.Token)
	project := writeCargoPackage(t, root, "checksum_fixture", crateVersion, "", "pub fn value() {}\n")
	runCargo(t, root, environment, "publish", "--allow-dirty", "--registry", cargoRegistryName, "--manifest-path", filepath.Join(project, "Cargo.toml"))
	registry.mu.Lock()
	published := registry.crates["checksum_fixture@"+crateVersion]
	if published == nil || len(published.archive) == 0 {
		registry.mu.Unlock()
		t.Fatal("synthetic crate was not published")
	}
	published.archive[len(published.archive)/2] ^= 1
	registry.mu.Unlock()
	freshHome := filepath.Join(root, "fresh-home")
	writeCargoHome(t, freshHome, registry.URL)
	freshEnvironment := cargoEnvironment(t, root, freshHome, registry.Token)
	consumer := writeCargoConsumer(t, root, "checksum-consumer", `checksum_fixture = { version = "=1.0.0", registry = "private" }`, "fn main() {}\n")
	output, err := runCargoExpectedFailure(t, root, freshEnvironment, "check", "--manifest-path", filepath.Join(consumer, "Cargo.toml"))
	if err == nil || !strings.Contains(strings.ToLower(output), "checksum") {
		t.Fatalf("Cargo did not reject the tampered crate due to its checksum: err=%v output=%s", err, output)
	}
}

func TestCargoDoesNotReportPendingReviewAsPublished(t *testing.T) {
	root := t.TempDir()
	registry := startRegistryFixture(t)
	registry.mu.Lock()
	registry.requireReview = true
	registry.mu.Unlock()
	cargoHome := filepath.Join(root, "cargo-home")
	writeCargoHome(t, cargoHome, registry.URL)
	environment := cargoEnvironment(t, root, cargoHome, registry.Token)
	project := writeCargoPackage(t, root, "review_fixture", crateVersion, "", "pub fn value() {}\n")
	output, err := runCargoExpectedFailure(t, root, environment, "publish", "--allow-dirty", "--registry", cargoRegistryName, "--manifest-path", filepath.Join(project, "Cargo.toml"))
	if err == nil || !strings.Contains(output, "human review") {
		t.Fatalf("Cargo reported success or an unrelated failure while review was required: err=%v output=%s", err, output)
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(registry.crates) != 0 || registry.publishRequests != 0 {
		t.Fatal("review-gated synthetic crate appeared as published")
	}
}

func TestFixtureCargoBuildMetadataIdentityRace(t *testing.T) {
	fixture := startRegistryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	type result struct {
		status int
		err    error
	}
	results := make(chan result, 2)
	for _, version := range []string{"1.0.0+first", "1.0.0+second"} {
		var archive bytes.Buffer
		gz := gzip.NewWriter(&archive)
		tw := tar.NewWriter(gz)
		manifest := "[package]\nname = \"identity_fixture\"\nversion = \"" + version + "\"\n"
		if err := tw.WriteHeader(&tar.Header{Name: "identity_fixture-" + version + "/Cargo.toml", Mode: 0o600, Size: int64(len(manifest))}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, manifest); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		metadata, err := json.Marshal(map[string]any{"name": "identity_fixture", "vers": version, "deps": []any{}, "features": map[string]any{}})
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		for _, part := range [][]byte{metadata, archive.Bytes()} {
			if err := binary.Write(&body, binary.LittleEndian, uint32(len(part))); err != nil {
				t.Fatal(err)
			}
			body.Write(part)
		}
		go func(payload []byte) {
			request, err := http.NewRequestWithContext(ctx, http.MethodPut, fixture.URL+"/api/v1/crates/new", bytes.NewReader(payload))
			if err != nil {
				results <- result{err: err}
				return
			}
			request.Header.Set("Authorization", fixture.Token)
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				results <- result{err: err}
				return
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			closeErr := response.Body.Close()
			results <- result{status: response.StatusCode, err: errors.Join(readErr, closeErr)}
		}(bytes.Clone(body.Bytes()))
	}
	var accepted, conflict int
	for range 2 {
		item := <-results
		if item.err != nil {
			t.Fatal(item.err)
		}
		switch item.status {
		case http.StatusOK:
			accepted++
		case http.StatusConflict:
			conflict++
		default:
			t.Fatalf("unexpected publish status %d", item.status)
		}
	}
	if accepted != 1 || conflict != 1 {
		t.Fatalf("build-metadata identity race accepted=%d conflict=%d", accepted, conflict)
	}
}

func TestCargoPackagesUnicodeNameLocally(t *testing.T) {
	root := t.TempDir()
	cargoHome := filepath.Join(root, "cargo-home")
	if err := os.Mkdir(cargoHome, 0o700); err != nil {
		t.Fatal(err)
	}
	environment := cargoEnvironment(t, root, cargoHome, "synthetic-unused-token")
	project := writeCargoPackage(t, root, "café_fixture", crateVersion, "[lib]\nname = \"cafe_fixture\"\n", "pub fn value() {}\n")
	output, err := runCargoExpectedFailure(t, root, environment, "package", "--offline", "--allow-dirty", "--no-verify", "--manifest-path", filepath.Join(project, "Cargo.toml"))
	if err != nil {
		t.Fatalf("Cargo could not package Unicode name: %v\n%s", err, output)
	}
}

func TestCargoUnicodeSparseRequestCharacterization(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	var base string
	fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index/config.json" {
			_, _ = fmt.Fprintf(w, `{"dl":%q}`, base+"/download")
			return
		}
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	fixture.Start()
	defer fixture.Close()
	base = fixture.URL
	root := t.TempDir()
	cargoHome := filepath.Join(root, "cargo-home")
	writeCargoHome(t, cargoHome, base)
	environment := cargoEnvironment(t, root, cargoHome, "synthetic-unused-token")
	project := writeCargoConsumer(t, root, "unicode-consumer", `cafe_fixture = { package = "café_fixture", version = "=1.0.0", registry = "private" }`, "fn main() {}\n")
	output, err := runCargoExpectedFailure(t, root, environment, "fetch", "--manifest-path", filepath.Join(project, "Cargo.toml"))
	if err == nil {
		t.Fatal("Cargo unexpectedly fetched missing Unicode package")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 0 || !strings.Contains(output, "not a char boundary") {
		t.Fatalf("Cargo Unicode index characterization changed: paths=%v output=%s", paths, output)
	}
}

func TestCargoUnicodeSparsePublishAndConsume(t *testing.T) {
	root := t.TempDir()
	fixture := startRegistryFixture(t)
	cargoHome := filepath.Join(root, "cargo-home")
	writeCargoHome(t, cargoHome, fixture.URL)
	environment := cargoEnvironment(t, root, cargoHome, fixture.Token)
	name := "testé_fixture"
	project := writeCargoPackage(t, root, name, crateVersion, "[lib]\nname = \"unicode_fixture\"\n", "pub fn value() -> &'static str { \"unicode-ok\" }\n")
	runCargo(t, root, environment, "publish", "--allow-dirty", "--registry", cargoRegistryName, "--manifest-path", filepath.Join(project, "Cargo.toml"))
	consumer := writeCargoConsumer(t, root, "unicode-consumer", `unicode_fixture = { package = "testé_fixture", version = "=1.0.0", registry = "private" }`, "fn main() { println!(\"{}\", unicode_fixture::value()); }\n")
	output := runCargo(t, root, environment, "run", "--manifest-path", filepath.Join(consumer, "Cargo.toml"))
	if !strings.Contains(output, "unicode-ok") {
		t.Fatalf("Cargo did not consume Unicode crate: %s", output)
	}
}

func startRegistryFixture(t *testing.T) *registryFixture {
	t.Helper()
	registry := &registryFixture{
		Token:  "Bearer " + hex.EncodeToString(randomBytes(t, 32)),
		crates: make(map[string]*publishedCrate),
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen for Cargo registry fixture:", err)
	}
	server := httptest.NewUnstartedServer(registry)
	server.Listener = listener
	server.Start()
	registry.URL = server.URL
	t.Cleanup(server.Close)
	return registry
}

func (registry *registryFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet && request.URL.Path == "/index/config.json" {
		registry.mu.Lock()
		registry.configRequests++
		registry.mu.Unlock()
		registry.writeJSON(writer, http.StatusOK, map[string]any{
			"dl":            registry.URL + "/crates/{crate}/{version}/download",
			"api":           registry.URL,
			"auth-required": true,
		})
		return
	}
	if !registry.authorized(writer, request) {
		return
	}
	if request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/index/") {
		registry.serveIndex(writer, request)
		return
	}
	if request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/crates/") && strings.HasSuffix(request.URL.Path, "/download") {
		registry.serveDownload(writer, request)
		return
	}
	if request.Method == http.MethodPut && request.URL.Path == "/api/v1/crates/new" {
		registry.servePublish(writer, request)
		return
	}
	if request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/api/v1/crates/") && strings.HasSuffix(request.URL.Path, "/yank") {
		registry.serveYank(writer, request)
		return
	}
	registry.mu.Lock()
	registry.unexpectedRequests = append(registry.unexpectedRequests, request.Method+" "+request.URL.Path)
	registry.mu.Unlock()
	registry.writeJSON(writer, http.StatusNotFound, map[string]any{"errors": []map[string]string{{"detail": "fixture route not found"}}})
}

func (registry *registryFixture) authorized(writer http.ResponseWriter, request *http.Request) bool {
	if request.Header.Get("Authorization") == registry.Token {
		return true
	}
	registry.mu.Lock()
	registry.unauthorizedPaths = append(registry.unauthorizedPaths, request.Method+" "+request.URL.Path)
	registry.mu.Unlock()
	writer.Header().Set("WWW-Authenticate", "Bearer")
	registry.writeAPIError(writer, http.StatusUnauthorized, "registry authentication required")
	return false
}

func (registry *registryFixture) serveIndex(writer http.ResponseWriter, request *http.Request) {
	name := path.Base(strings.TrimPrefix(request.URL.Path, "/index/"))
	indexPath, err := cargo.SparseIndexPath(name)
	if err != nil || request.URL.Path != "/index/"+indexPath {
		registry.recordUnexpected(request)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	registry.mu.Lock()
	registry.indexRequests++
	lines := make([]cargoIndexEntry, 0)
	for key, published := range registry.crates {
		if strings.HasPrefix(key, name+"@") {
			lines = append(lines, published.entry)
		}
	}
	registry.mu.Unlock()
	if len(lines) == 0 {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	sort.Slice(lines, func(first, second int) bool {
		return lines[first].Version < lines[second].Version
	})
	var body bytes.Buffer
	for _, line := range lines {
		encoded, err := json.Marshal(line)
		if err != nil {
			http.Error(writer, "fixture index encoding failed", http.StatusInternalServerError)
			return
		}
		body.Write(encoded)
		body.WriteByte('\n')
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(body.Bytes())
}

func (registry *registryFixture) serveDownload(writer http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) != 4 {
		registry.recordUnexpected(request)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	name, version := parts[1], parts[2]
	identity, err := cargo.VersionIdentity(version)
	if err != nil {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	registry.mu.Lock()
	registry.downloadRequests++
	published := registry.crates[name+"@"+identity]
	var archive []byte
	if published != nil && published.entry.Version == version {
		archive = append([]byte(nil), published.archive...)
	}
	registry.mu.Unlock()
	if len(archive) == 0 {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", strconv.Itoa(len(archive)))
	_, _ = writer.Write(archive)
}

func (registry *registryFixture) servePublish(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxUploadBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		registry.writeAPIError(writer, http.StatusRequestEntityTooLarge, "upload exceeds fixture limit")
		return
	}
	metadata, archive, err := parsePublishBody(body)
	if err != nil {
		registry.writeAPIError(writer, http.StatusBadRequest, "invalid Cargo publish payload")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	var staged bytes.Buffer
	framed, err := cargo.ReadPublishFrame(ctx, bytes.NewReader(body), &staged, 1<<20, maxUploadBytes)
	archiveHash := sha256.Sum256(archive)
	if err != nil || cargo.CheckMetadataJSON(framed.Metadata) != nil || !bytes.Equal(staged.Bytes(), archive) || framed.Size != int64(len(archive)) || framed.SHA256 != hex.EncodeToString(archiveHash[:]) {
		registry.writeAPIError(writer, http.StatusBadRequest, "Cargo publish framing mismatch")
		return
	}
	entry, err := makeIndexEntry(metadata, archive)
	if err != nil {
		registry.writeAPIError(writer, http.StatusBadRequest, "invalid Cargo publish metadata")
		return
	}
	projection, err := cargo.ValidateStagedPublication(ctx, framed, bytes.NewReader(staged.Bytes()), cargo.ArchiveLimits{MaxCompressedBytes: maxUploadBytes, MaxUncompressedBytes: 16 << 20, MaxFiles: 1000, MaxManifestBytes: 1 << 20}, "sparse+"+registry.URL+"/index/", "https://github.com/rust-lang/crates.io-index")
	if err != nil {
		registry.writeAPIError(writer, http.StatusBadRequest, "Cargo staged publication rejected")
		return
	}
	projectedJSON, err := json.Marshal(projection)
	entry = cargoIndexEntry{}
	if err != nil || json.Unmarshal(projectedJSON, &entry) != nil {
		registry.writeAPIError(writer, http.StatusBadRequest, "Cargo index projection invalid")
		return
	}
	if err := validateCrateArchive(metadata.Name, metadata.Version, archive); err != nil {
		registry.writeAPIError(writer, http.StatusBadRequest, "crate archive does not match publication metadata")
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.requireReview {
		registry.writeAPIError(writer, http.StatusConflict, "human review required; use the registry publication workflow")
		return
	}
	identity, err := cargo.VersionIdentity(metadata.Version)
	if err != nil {
		registry.writeAPIError(writer, http.StatusBadRequest, "crate version invalid")
		return
	}
	key := metadata.Name + "@" + identity
	if _, exists := registry.crates[key]; exists {
		registry.writeAPIError(writer, http.StatusConflict, "crate version already published")
		return
	}
	registry.crates[key] = &publishedCrate{
		metadata: metadata,
		entry:    entry,
		archive:  append([]byte(nil), archive...),
	}
	registry.publishRequests++
	registry.writeJSON(writer, http.StatusOK, map[string]any{
		"ok": true,
		"warnings": map[string]any{
			"invalid_categories": []string{},
			"invalid_badges":     []string{},
			"other":              []string{},
		},
	})
}

func (registry *registryFixture) serveYank(writer http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) != 6 {
		registry.recordUnexpected(request)
		registry.writeAPIError(writer, http.StatusNotFound, "crate version not found")
		return
	}
	name, version := parts[3], parts[4]
	identity, err := cargo.VersionIdentity(version)
	if err != nil {
		registry.writeAPIError(writer, http.StatusNotFound, "crate version not found")
		return
	}
	registry.mu.Lock()
	published := registry.crates[name+"@"+identity]
	if published != nil && published.entry.Version == version {
		published.entry.Yanked = true
		registry.yankRequests++
	} else {
		published = nil
	}
	registry.mu.Unlock()
	if published == nil {
		registry.writeAPIError(writer, http.StatusNotFound, "crate version not found")
		return
	}
	registry.writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
}

func (registry *registryFixture) writeAPIError(writer http.ResponseWriter, status int, detail string) {
	registry.writeJSON(writer, status, map[string]any{"errors": []map[string]string{{"detail": detail}}})
}

func (registry *registryFixture) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		return
	}
}

func (registry *registryFixture) recordUnexpected(request *http.Request) {
	registry.mu.Lock()
	registry.unexpectedRequests = append(registry.unexpectedRequests, request.Method+" "+request.URL.Path)
	registry.mu.Unlock()
}

func (registry *registryFixture) isYanked(name, version string) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	published := registry.crates[name+"@"+version]
	return published != nil && published.entry.Yanked
}

func (registry *registryFixture) unauthorizedPathsSnapshot() []string {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return append([]string(nil), registry.unauthorizedPaths...)
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal("generate synthetic registry credential:", err)
	}
	return value
}

func parsePublishBody(body []byte) (cargoPublishMetadata, []byte, error) {
	reader := bytes.NewReader(body)
	metadataLength, err := readUint32(reader)
	if err != nil || metadataLength == 0 || metadataLength > 1<<20 || uint64(metadataLength) > uint64(reader.Len()) {
		return cargoPublishMetadata{}, nil, errors.New("invalid metadata length")
	}
	metadataBytes := make([]byte, metadataLength)
	if _, err := io.ReadFull(reader, metadataBytes); err != nil {
		return cargoPublishMetadata{}, nil, err
	}
	var metadata cargoPublishMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return cargoPublishMetadata{}, nil, err
	}
	archiveLength, err := readUint32(reader)
	if err != nil || archiveLength == 0 || archiveLength > maxUploadBytes || uint64(archiveLength) != uint64(reader.Len()) {
		return cargoPublishMetadata{}, nil, errors.New("invalid archive length")
	}
	archive := make([]byte, archiveLength)
	if _, err := io.ReadFull(reader, archive); err != nil {
		return cargoPublishMetadata{}, nil, err
	}
	if reader.Len() != 0 || metadata.Name == "" || metadata.Version == "" {
		return cargoPublishMetadata{}, nil, errors.New("trailing bytes or missing crate identity")
	}
	return metadata, archive, nil
}

func readUint32(reader io.Reader) (uint32, error) {
	var encoded [4]byte
	if _, err := io.ReadFull(reader, encoded[:]); err != nil {
		return 0, err
	}
	return uint32(encoded[0]) | uint32(encoded[1])<<8 | uint32(encoded[2])<<16 | uint32(encoded[3])<<24, nil
}

func makeIndexEntry(metadata cargoPublishMetadata, archive []byte) (cargoIndexEntry, error) {
	checksum := sha256.Sum256(archive)
	dependencies := make([]cargoIndexDependency, 0, len(metadata.Dependencies))
	for _, dependency := range metadata.Dependencies {
		if dependency.Name == "" || dependency.VersionReq == "" {
			return cargoIndexEntry{}, errors.New("dependency name and version requirement are required")
		}
		name := dependency.Name
		packageName := dependency.ExplicitNameInTOML
		if packageName != nil {
			name, packageName = *packageName, &dependency.Name
		}
		kind := dependency.Kind
		if kind == "" {
			kind = "normal"
		}
		dependencies = append(dependencies, cargoIndexDependency{
			Name:            name,
			Requirement:     dependency.VersionReq,
			Features:        dependency.Features,
			Optional:        dependency.Optional,
			DefaultFeatures: dependency.DefaultFeatures,
			Target:          dependency.Target,
			Kind:            kind,
			Registry:        dependency.Registry,
			Package:         packageName,
		})
	}
	if metadata.Features == nil {
		metadata.Features = map[string][]string{}
	}
	return cargoIndexEntry{
		Name:         metadata.Name,
		Version:      metadata.Version,
		Dependencies: dependencies,
		Checksum:     hex.EncodeToString(checksum[:]),
		Features:     metadata.Features,
		Links:        metadata.Links,
		RustVersion:  metadata.RustVersion,
	}, nil
}

func validateCrateArchive(expectedName, expectedVersion string, archive []byte) error {
	reader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	defer reader.Close()
	tarReader := tar.NewReader(io.LimitReader(reader, maxUploadBytes))
	manifestPath := expectedName + "-" + expectedVersion + "/Cargo.toml"
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("crate archive is missing Cargo.toml")
		}
		if err != nil {
			return err
		}
		if header.Name == manifestPath {
			manifest, err := io.ReadAll(io.LimitReader(tarReader, 1<<20))
			if err != nil {
				return err
			}
			if len(manifest) >= 1<<20 {
				return errors.New("Cargo.toml exceeds fixture limit")
			}
			if !strings.Contains(string(manifest), "name = \""+expectedName+"\"") || !strings.Contains(string(manifest), "version = \""+expectedVersion+"\"") {
				return errors.New("Cargo.toml crate identity does not match upload metadata")
			}
			return nil
		}
	}
}

func writeCargoHome(t *testing.T, cargoHome, registryURL string) {
	t.Helper()
	if err := os.MkdirAll(cargoHome, 0o700); err != nil {
		t.Fatal("create isolated Cargo home:", err)
	}
	configuration := fmt.Sprintf(`[registry]
global-credential-providers = ["cargo:token"]

[registries.%s]
index = "sparse+%s/index/"
credential-provider = "cargo:token"
`, cargoRegistryName, registryURL)
	if err := os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte(configuration), 0o600); err != nil {
		t.Fatal("write isolated Cargo registry config:", err)
	}
}

func cargoEnvironment(t *testing.T, root, cargoHome, token string) []string {
	t.Helper()
	sysroot := strings.TrimSpace(runCommandVersion(t, "rustup", "run", rustToolchain, "rustc", "--print", "sysroot"))
	toolchainBin := filepath.Join(sysroot, "bin")
	if _, err := os.Stat(filepath.Join(toolchainBin, "cargo")); err != nil {
		t.Fatalf("Cargo binary is missing from active Rust toolchain %q: %v", toolchainBin, err)
	}
	values := []string{
		"PATH=" + toolchainBin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"CARGO_HOME=" + cargoHome,
		"CARGO_TARGET_DIR=" + filepath.Join(root, "target"),
		"CARGO_REGISTRIES_PRIVATE_TOKEN=" + token,
		"RUSTUP_TOOLCHAIN=" + rustToolchain,
		"CARGO_HTTP_TIMEOUT=20",
		"CARGO_HTTP_MULTIPLEXING=false",
		"CARGO_NET_RETRY=0",
		"CARGO_NET_OFFLINE=false",
		"CARGO_TERM_COLOR=never",
		"HTTP_PROXY=http://127.0.0.1:9",
		"HTTPS_PROXY=http://127.0.0.1:9",
		"http_proxy=http://127.0.0.1:9",
		"https_proxy=http://127.0.0.1:9",
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
	}
	if value := os.Getenv("RUSTUP_HOME"); value != "" {
		values = append(values, "RUSTUP_HOME="+value)
	}
	if value := os.Getenv("RUSTUP_TOOLCHAIN"); value != "" {
		values = append(values, "RUSTUP_TOOLCHAIN="+value)
	}
	return values
}

func writeCargoPackage(t *testing.T, root, name, version, extraManifest, source string) string {
	t.Helper()
	project := filepath.Join(root, "publish", name)
	if err := os.MkdirAll(filepath.Join(project, "src"), 0o700); err != nil {
		t.Fatal("create Cargo package source:", err)
	}
	manifest := fmt.Sprintf(`[package]
name = %q
version = %q
edition = "2021"

%s
`, name, version, extraManifest)
	if err := os.WriteFile(filepath.Join(project, "Cargo.toml"), []byte(manifest), 0o600); err != nil {
		t.Fatal("write Cargo package manifest:", err)
	}
	if err := os.WriteFile(filepath.Join(project, "src", "lib.rs"), []byte(source), 0o600); err != nil {
		t.Fatal("write Cargo package source:", err)
	}
	return project
}

func writeCargoConsumer(t *testing.T, root, name, dependencies, source string) string {
	t.Helper()
	project := filepath.Join(root, "consume", name)
	if err := os.MkdirAll(filepath.Join(project, "src"), 0o700); err != nil {
		t.Fatal("create Cargo consumer source:", err)
	}
	manifest := fmt.Sprintf(`[package]
name = %q
version = "0.1.0"
edition = "2021"

[dependencies]
%s
`, name, dependencies)
	if err := os.WriteFile(filepath.Join(project, "Cargo.toml"), []byte(manifest), 0o600); err != nil {
		t.Fatal("write Cargo consumer manifest:", err)
	}
	if err := os.WriteFile(filepath.Join(project, "src", "main.rs"), []byte(source), 0o600); err != nil {
		t.Fatal("write Cargo consumer source:", err)
	}
	return project
}

func runCargo(t *testing.T, root string, environment []string, args ...string) string {
	t.Helper()
	output, err := runCargoCommand(root, environment, args...)
	if err != nil {
		t.Fatalf("cargo %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}

func runCargoExpectedFailure(t *testing.T, root string, environment []string, args ...string) (string, error) {
	t.Helper()
	return runCargoCommand(root, environment, args...)
}

func runCargoCommand(root string, environment []string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cargoPath, err := executableFromEnvironment("cargo", environment)
	if err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, cargoPath, args...)
	command.Dir = root
	command.Env = environment
	output, err := command.CombinedOutput()
	return string(output), err
}

func executableFromEnvironment(name string, environment []string) (string, error) {
	for _, value := range environment {
		if !strings.HasPrefix(value, "PATH=") {
			continue
		}
		for _, directory := range filepath.SplitList(strings.TrimPrefix(value, "PATH=")) {
			candidate := filepath.Join(directory, name)
			info, err := os.Stat(candidate)
			if err != nil {
				continue
			}
			if !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("%s is not available in the configured subprocess PATH", name)
}

func runCommandVersion(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}
