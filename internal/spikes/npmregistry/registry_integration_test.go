//go:build integration

package npmregistry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"private-registry/internal/npm"
)

const (
	npmNodeVersion = "v24.21.0"
	npmVersion     = "11.19.0"
	npmScope       = "@fixture"
	npmLeafName    = "@fixture/registry_fixture_leaf"
	npmParentName  = "@fixture/registry_fixture_parent"
	npmTestVersion = "1.0.0"
	maxRequestSize = 12 << 20
)

type npmAttachment struct {
	ContentType string `json:"content_type"`
	Data        string `json:"data"`
	Length      int    `json:"length"`
}

type npmPublishDocument struct {
	ID          string                    `json:"_id"`
	Name        string                    `json:"name"`
	Versions    map[string]map[string]any `json:"versions"`
	DistTags    map[string]string         `json:"dist-tags"`
	Attachments map[string]npmAttachment  `json:"_attachments"`
}

type npmPublishedVersion struct {
	manifest map[string]any
	tarball  []byte
}

type npmPackage struct {
	versions map[string]*npmPublishedVersion
	distTags map[string]string
}

type npmRegistryFixture struct {
	URL                string
	Token              string
	mu                 sync.Mutex
	packages           map[string]*npmPackage
	metadataRequests   int
	tarballRequests    int
	publishRequests    int
	publishConflicts   int
	distTagRequests    int
	unauthorizedPaths  []string
	unexpectedRequests []string
	requireReview      bool
	observedVersions   []string
	observedArchives   []string
}

func TestNPMBuildMetadataCharacterization(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	registry := startNPMRegistry(t)
	userConfig := writeNPMUserConfig(t, root, registry.URL, registry.Token)
	environment := npmEnvironment(root, userConfig, filepath.Dir(nodePath))
	project := writeNPMFixturePackage(t, root, npmLeafName, "module.exports = 1;\n", nil)
	manifestPath := filepath.Join(project, "package.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["version"] = "1.0.0+build.1"
	data, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, npmPath, "publish", "--registry", registry.URL, "--tag", "latest", "--ignore-scripts", "--json", project)
	command.Dir = root
	command.Env = environment
	_, publishErr := command.CombinedOutput()
	registry.mu.Lock()
	versions := append([]string(nil), registry.observedVersions...)
	archives := append([]string(nil), registry.observedArchives...)
	registry.mu.Unlock()
	if publishErr != nil || len(versions) != 1 || versions[0] != "1.0.0" || len(archives) != 1 || archives[0] != "1.0.0+build.1" {
		t.Fatalf("npm build metadata normalization changed: err=%v envelope=%v archive=%v", publishErr, versions, archives)
	}
	consumer := filepath.Join(root, "build-metadata-consumer")
	if err := os.Mkdir(consumer, 0o700); err != nil {
		t.Fatal(err)
	}
	consumerManifest := `{"name":"synthetic-consumer","version":"1.0.0","private":true,"dependencies":{"@fixture/registry_fixture_leaf":"1.0.0"}}`
	if err := os.WriteFile(filepath.Join(consumer, "package.json"), []byte(consumerManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	freshEnvironment := npmEnvironment(filepath.Join(root, "fresh-npm-state"), userConfig, filepath.Dir(nodePath))
	runNPM(t, npmPath, consumer, freshEnvironment, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--registry", registry.URL)
	output := runCommand(t, nodePath, consumer, freshEnvironment, "-e", `process.stdout.write(String(require("@fixture/registry_fixture_leaf")))`)
	if output != "1" {
		t.Fatalf("npm did not consume the normalized package: %q", output)
	}
}

func TestNPMBuildMetadataVersionsCollideInFixture(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	registry := startNPMRegistry(t)
	userConfig := writeNPMUserConfig(t, root, registry.URL, registry.Token)
	environment := npmEnvironment(root, userConfig, filepath.Dir(nodePath))
	project := writeNPMFixturePackage(t, root, npmLeafName, "module.exports = 1;\n", nil)
	manifestPath := filepath.Join(project, "package.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	setVersion := func(version string) {
		t.Helper()
		manifest["version"] = version
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setVersion("1.0.0+first")
	runNPM(t, npmPath, root, environment, "publish", "--registry", registry.URL, "--tag", "latest", "--ignore-scripts", "--json", project)
	setVersion("1.0.0+second")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, npmPath, "publish", "--registry", registry.URL, "--tag", "latest", "--ignore-scripts", "--json", project)
	command.Dir = root
	command.Env = environment
	output, err := command.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("You cannot publish over the previously published versions: 1.0.0.")) {
		t.Fatal("npm did not reject the previously published normalized version")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	packageData := registry.packages[npmLeafName]
	if packageData == nil || len(packageData.versions) != 1 || packageData.versions["1.0.0"] == nil || registry.publishRequests != 1 || registry.publishConflicts != 0 || len(registry.observedVersions) != 1 {
		t.Fatal("fixture received an unexpected second publish request or version")
	}
}

func TestNPMDoesNotReportPendingReviewAsPublished(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("Node.js is required for the npm registry integration contract:", err)
	}
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		t.Fatal("npm is required for the npm registry integration contract:", err)
	}
	root := t.TempDir()
	registry := startNPMRegistry(t)
	registry.mu.Lock()
	registry.requireReview = true
	registry.mu.Unlock()
	userConfig := writeNPMUserConfig(t, root, registry.URL, registry.Token)
	environment := npmEnvironment(root, userConfig, filepath.Dir(nodePath))
	project := writeNPMFixturePackage(t, root, npmLeafName, "module.exports = 1;\n", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, npmPath, "publish", "--registry", registry.URL, "--tag", "latest", "--ignore-scripts", "--json", project)
	command.Dir = root
	command.Env = environment
	output, err := command.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("human review")) {
		t.Fatalf("npm reported success or an unrelated error while review was required: %v", err)
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(registry.packages) != 0 || registry.publishRequests != 0 {
		t.Fatal("review-gated synthetic package appeared as published")
	}
}

func TestNPMRejectsTamperedTarball(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("Node.js is required for the npm registry integration contract:", err)
	}
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		t.Fatal("npm is required for the npm registry integration contract:", err)
	}
	root := t.TempDir()
	registry := startNPMRegistry(t)
	userConfig := writeNPMUserConfig(t, root, registry.URL, registry.Token)
	environment := npmEnvironment(root, userConfig, filepath.Dir(nodePath))
	project := writeNPMFixturePackage(t, root, npmLeafName, "module.exports = 1;\n", nil)
	runNPM(t, npmPath, root, environment, "publish", "--registry", registry.URL, "--tag", "latest", "--ignore-scripts", "--json", project)
	registry.mu.Lock()
	packageData := registry.packages[npmLeafName]
	if packageData == nil || packageData.versions[npmTestVersion] == nil || len(packageData.versions[npmTestVersion].tarball) == 0 {
		registry.mu.Unlock()
		t.Fatal("synthetic npm tarball was not published")
	}
	tarball := packageData.versions[npmTestVersion].tarball
	tarball[len(tarball)/2] ^= 1
	registry.mu.Unlock()
	consumer := filepath.Join(root, "tampered-consumer")
	if err := os.Mkdir(consumer, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := `{"name":"synthetic-consumer","version":"1.0.0","private":true,"dependencies":{"@fixture/registry_fixture_leaf":"1.0.0"}}`
	if err := os.WriteFile(filepath.Join(consumer, "package.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	freshEnvironment := npmEnvironment(filepath.Join(root, "fresh-npm-state"), userConfig, filepath.Dir(nodePath))
	freshEnvironment = append(freshEnvironment, "npm_config_fetch_retries=0")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, npmPath, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--registry", registry.URL)
	command.Dir = consumer
	command.Env = freshEnvironment
	output, err := command.CombinedOutput()
	if err == nil || !bytes.Contains(bytes.ToLower(output), []byte("integrity")) {
		t.Fatalf("npm did not reject tampered tarball due to integrity: %v", err)
	}
}

func TestNPMClientPublishesInstallsAndMovesScopedDistTag(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("Node.js is required for the npm registry integration contract:", err)
	}
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		t.Fatal("npm is required for the npm registry integration contract:", err)
	}
	nodeVersion := runVersion(t, nodePath, "--version")
	if nodeVersion != npmNodeVersion {
		t.Fatalf("unsupported Node.js integration baseline %q; expected %q", nodeVersion, npmNodeVersion)
	}
	installedNPMVersion := runVersion(t, npmPath, "--version")
	if installedNPMVersion != npmVersion {
		t.Fatalf("unsupported npm integration baseline %q; expected %q", installedNPMVersion, npmVersion)
	}

	root := t.TempDir()
	registry := startNPMRegistry(t)
	userConfig := writeNPMUserConfig(t, root, registry.URL, registry.Token)
	binDirectory := filepath.Dir(nodePath)
	environment := npmEnvironment(root, userConfig, binDirectory)

	leafProject := writeNPMFixturePackage(t, root, npmLeafName, `module.exports = function () { return "private-leaf-value"; };
`, nil)
	leafManifestPath := filepath.Join(leafProject, "package.json")
	leafManifest, err := os.ReadFile(leafManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var leafFields map[string]json.RawMessage
	if err := json.Unmarshal(leafManifest, &leafFields); err != nil {
		t.Fatal(err)
	}
	leafFields["exports"] = json.RawMessage(`{"node":"./index.js","default":"./missing.js"}`)
	leafFields["browser"] = json.RawMessage(`"./index.js"`)
	leafFields["typesVersions"] = json.RawMessage(`{">=5.0":{"*": ["types/*"]},"*":{"*": ["legacy/*"]}}`)
	leafManifest, err = json.Marshal(leafFields)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafManifestPath, leafManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	parentProject := writeNPMFixturePackage(t, root, npmParentName, `const leaf = require("@fixture/registry_fixture_leaf");
module.exports = function () { return "parent/" + leaf(); };
`, map[string]string{npmLeafName: "1.0.0"})
	runNPM(t, npmPath, root, environment, "publish", "--registry", registry.URL, "--tag", "latest", "--ignore-scripts", "--json", leafProject)
	runNPM(t, npmPath, root, environment, "publish", "--registry", registry.URL, "--tag", "latest", "--ignore-scripts", "--json", parentProject)

	consumer := writeNPMConsumer(t, root)
	consumerEnvironment := npmEnvironment(filepath.Join(root, "consumer-npm-state"), userConfig, binDirectory)
	runNPM(t, npmPath, consumer, consumerEnvironment, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--registry", registry.URL)
	if _, err := os.Stat(filepath.Join(consumer, "package-lock.json")); err != nil {
		t.Fatalf("npm did not produce a lockfile: %v", err)
	}
	runNPM(t, npmPath, consumer, consumerEnvironment, "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--registry", registry.URL)
	output := runCommand(t, nodePath, consumer, consumerEnvironment, "-e", `process.stdout.write(require("@fixture/registry_fixture_parent")())`)
	if strings.TrimSpace(output) != "parent/private-leaf-value" {
		t.Fatalf("npm ci did not install the scoped transitive private package: %q", strings.TrimSpace(output))
	}

	runNPM(t, npmPath, root, environment, "dist-tag", "add", npmParentName+"@"+npmTestVersion, "next", "--registry", registry.URL)
	view := runNPM(t, npmPath, root, environment, "view", npmParentName, "dist-tags", "--json", "--registry", registry.URL)
	if !strings.Contains(view, `"next": "1.0.0"`) && !strings.Contains(view, `"next":"1.0.0"`) {
		t.Fatalf("npm did not observe the updated scoped dist-tag: %s", view)
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.publishRequests != 2 {
		t.Errorf("npm publish requests = %d, want 2", registry.publishRequests)
	}
	if registry.distTagRequests != 1 {
		t.Errorf("npm dist-tag requests = %d, want 1", registry.distTagRequests)
	}
	if registry.metadataRequests == 0 || registry.tarballRequests < 2 {
		t.Errorf("expected packument and tarball reads; metadata=%d tarballs=%d", registry.metadataRequests, registry.tarballRequests)
	}
	if len(registry.unauthorizedPaths) != 0 {
		t.Errorf("npm sent requests to protected routes without the scoped token: %v", registry.unauthorizedPaths)
	}
	if len(registry.unexpectedRequests) != 0 {
		t.Errorf("npm requested unsupported local registry routes: %v", registry.unexpectedRequests)
	}
}

func startNPMRegistry(t *testing.T) *npmRegistryFixture {
	t.Helper()
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatal("generate synthetic npm credential:", err)
	}
	registry := &npmRegistryFixture{
		Token:    base64.RawURLEncoding.EncodeToString(token),
		packages: make(map[string]*npmPackage),
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen for npm registry fixture:", err)
	}
	server := httptest.NewUnstartedServer(registry)
	server.Listener = listener
	server.Start()
	registry.URL = server.URL + "/"
	t.Cleanup(server.Close)
	return registry
}

func (registry *npmRegistryFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	path := request.URL.Path
	if !registry.authorized(writer, request) {
		return
	}
	if request.Method == http.MethodPut && strings.HasPrefix(path, "/@fixture/") && !strings.Contains(path, "/-/package/") {
		registry.servePublish(writer, request)
		return
	}
	if request.Method == http.MethodGet && strings.HasPrefix(path, "/-/package/") && strings.HasSuffix(path, "/dist-tags") {
		registry.serveDistTags(writer, request)
		return
	}
	if request.Method == http.MethodPut && strings.HasPrefix(path, "/-/package/") && strings.Contains(path, "/dist-tags/") {
		registry.serveDistTag(writer, request)
		return
	}
	if request.Method == http.MethodGet && strings.HasPrefix(path, "/@fixture/") && strings.Contains(path, "/-/") {
		registry.serveTarball(writer, request)
		return
	}
	if request.Method == http.MethodGet && strings.HasPrefix(path, "/@fixture/") {
		registry.servePackument(writer, request)
		return
	}
	registry.mu.Lock()
	registry.unexpectedRequests = append(registry.unexpectedRequests, request.Method+" "+request.URL.EscapedPath())
	registry.mu.Unlock()
	registry.writeJSON(writer, http.StatusNotFound, map[string]any{"error": "fixture route not found"})
}

func (registry *npmRegistryFixture) authorized(writer http.ResponseWriter, request *http.Request) bool {
	if request.Header.Get("Authorization") == "Bearer "+registry.Token {
		return true
	}
	registry.mu.Lock()
	registry.unauthorizedPaths = append(registry.unauthorizedPaths, request.Method+" "+request.URL.EscapedPath())
	registry.mu.Unlock()
	writer.Header().Set("WWW-Authenticate", "Bearer")
	registry.writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	return false
}

func (registry *npmRegistryFixture) servePublish(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestSize)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		registry.writeJSON(writer, http.StatusRequestEntityTooLarge, map[string]string{"error": "publish document too large"})
		return
	}
	var document npmPublishDocument
	if err := json.Unmarshal(body, &document); err != nil {
		registry.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid publish document"})
		return
	}
	if document.Name == "" || document.Name != document.ID || len(document.Versions) != 1 || len(document.Attachments) != 1 {
		registry.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid package identity or attachment count"})
		return
	}
	requestName, err := url.PathUnescape(strings.TrimPrefix(request.URL.EscapedPath(), "/"))
	if err != nil || requestName != document.Name {
		registry.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "request and document package names differ"})
		return
	}
	var version string
	var manifest map[string]any
	for version, manifest = range document.Versions {
		break
	}
	registry.mu.Lock()
	registry.observedVersions = append(registry.observedVersions, version)
	registry.mu.Unlock()
	if manifest["name"] != document.Name || manifest["version"] != version {
		registry.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "manifest identity mismatch"})
		return
	}
	var attachment npmAttachment
	for _, attachment = range document.Attachments {
		break
	}
	tarball, err := base64.StdEncoding.DecodeString(attachment.Data)
	if err != nil || len(tarball) == 0 || len(tarball) != attachment.Length {
		registry.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid package attachment"})
		return
	}
	if archiveVersion, err := fixtureArchiveVersion(tarball); err == nil {
		registry.mu.Lock()
		registry.observedArchives = append(registry.observedArchives, archiveVersion)
		registry.mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	var staged bytes.Buffer
	parsed, err := npm.ReadPublishDocument(ctx, bytes.NewReader(body), &staged, requestName, maxRequestSize, maxRequestSize)
	digest := sha512.Sum512(tarball)
	if err != nil || parsed.Name != document.Name || parsed.Version != version || parsed.Size != int64(len(tarball)) || !bytes.Equal(staged.Bytes(), tarball) || parsed.Integrity != "sha512-"+base64.StdEncoding.EncodeToString(digest[:]) {
		registry.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "experimental npm envelope rejected"})
		return
	}
	if err := npm.ValidateStagedPublication(ctx, parsed, bytes.NewReader(staged.Bytes()), npm.ArchiveLimits{MaxCompressedBytes: maxRequestSize, MaxUncompressedBytes: 32 << 20, MaxEntries: 1000, MaxManifestBytes: 1 << 20}); err != nil {
		registry.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "experimental npm archive rejected"})
		return
	}
	if err := validateNPMArchive(document.Name, tarball); err != nil {
		registry.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid package archive"})
		return
	}
	sha1Digest := sha1.Sum(tarball)
	sha512Digest := sha512.Sum512(tarball)
	shasum := hex.EncodeToString(sha1Digest[:])
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(sha512Digest[:])
	manifest["dist"] = map[string]any{
		"tarball":   registry.tarballURL(document.Name, version),
		"shasum":    shasum,
		"integrity": integrity,
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.requireReview {
		registry.writeJSON(writer, http.StatusConflict, map[string]string{"error": "human review required; use the registry publication workflow"})
		return
	}
	packageData := registry.packages[document.Name]
	if packageData == nil {
		packageData = &npmPackage{versions: make(map[string]*npmPublishedVersion), distTags: make(map[string]string)}
		registry.packages[document.Name] = packageData
	}
	if _, exists := packageData.versions[version]; exists {
		registry.publishConflicts++
		registry.writeJSON(writer, http.StatusConflict, map[string]string{"error": "package version already published"})
		return
	}
	packageData.versions[version] = &npmPublishedVersion{
		manifest: manifest,
		tarball:  append([]byte(nil), tarball...),
	}
	for tag, tagVersion := range document.DistTags {
		packageData.distTags[tag] = tagVersion
	}
	registry.publishRequests++
	registry.writeJSON(writer, http.StatusCreated, map[string]any{"ok": true, "id": document.Name, "rev": "1-fixture"})
}

func fixtureArchiveVersion(data []byte) (string, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer reader.Close()
	tarReader := tar.NewReader(io.LimitReader(reader, maxRequestSize))
	for {
		header, err := tarReader.Next()
		if err != nil {
			return "", err
		}
		if header.Name != "package/package.json" {
			continue
		}
		var manifest struct {
			Version string `json:"version"`
		}
		if err := json.NewDecoder(io.LimitReader(tarReader, 1<<20)).Decode(&manifest); err != nil {
			return "", err
		}
		return manifest.Version, nil
	}
}

func (registry *npmRegistryFixture) servePackument(writer http.ResponseWriter, request *http.Request) {
	name, err := url.PathUnescape(strings.TrimPrefix(request.URL.EscapedPath(), "/"))
	if err != nil {
		registry.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid package path"})
		return
	}
	registry.mu.Lock()
	registry.metadataRequests++
	packageData := registry.packages[name]
	if packageData == nil {
		registry.mu.Unlock()
		registry.writeJSON(writer, http.StatusNotFound, map[string]string{"error": "package not found"})
		return
	}
	versions := make(map[string]any, len(packageData.versions))
	for version, published := range packageData.versions {
		versions[version] = published.manifest
	}
	tags := make(map[string]string, len(packageData.distTags))
	for tag, version := range packageData.distTags {
		tags[tag] = version
	}
	registry.mu.Unlock()
	registry.writeJSON(writer, http.StatusOK, map[string]any{
		"_id":       name,
		"name":      name,
		"dist-tags": tags,
		"versions":  versions,
	})
}

func (registry *npmRegistryFixture) serveTarball(writer http.ResponseWriter, request *http.Request) {
	segments := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(segments) != 4 || segments[0] != "@fixture" || segments[2] != "-" {
		registry.recordUnexpected(request)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	packageName := "@fixture/" + segments[1]
	filename := strings.TrimSuffix(segments[3], ".tgz")
	versionSeparator := strings.LastIndex(filename, "-")
	if versionSeparator < 1 {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	version := filename[versionSeparator+1:]
	registry.mu.Lock()
	registry.tarballRequests++
	packageData := registry.packages[packageName]
	var published *npmPublishedVersion
	if packageData != nil {
		published = packageData.versions[version]
	}
	var tarball []byte
	if published != nil {
		tarball = append([]byte(nil), published.tarball...)
	}
	registry.mu.Unlock()
	if len(tarball) == 0 {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(tarball)))
	_, _ = writer.Write(tarball)
}

func (registry *npmRegistryFixture) serveDistTag(writer http.ResponseWriter, request *http.Request) {
	segments := strings.Split(strings.Trim(request.URL.EscapedPath(), "/"), "/")
	if len(segments) != 5 || segments[0] != "-" || segments[1] != "package" || segments[3] != "dist-tags" {
		registry.recordUnexpected(request)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	packageName, err := url.PathUnescape(segments[2])
	if err != nil || !strings.HasPrefix(packageName, npmScope+"/") {
		registry.recordUnexpected(request)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	tag := segments[4]
	body, err := io.ReadAll(io.LimitReader(request.Body, 1024))
	if err != nil {
		registry.writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid dist-tag body"})
		return
	}
	version := strings.TrimSpace(strings.Trim(string(body), `"`))
	registry.mu.Lock()
	packageData := registry.packages[packageName]
	if packageData == nil {
		registry.mu.Unlock()
		registry.writeJSON(writer, http.StatusNotFound, map[string]string{"error": "package not found"})
		return
	}
	if packageData.versions[version] == nil {
		registry.mu.Unlock()
		registry.writeJSON(writer, http.StatusNotFound, map[string]string{"error": "version not found"})
		return
	}
	packageData.distTags[tag] = version
	registry.distTagRequests++
	registry.mu.Unlock()
	registry.writeJSON(writer, http.StatusOK, map[string]bool{"ok": true})
}

func (registry *npmRegistryFixture) serveDistTags(writer http.ResponseWriter, request *http.Request) {
	segments := strings.Split(strings.Trim(request.URL.EscapedPath(), "/"), "/")
	if len(segments) != 4 || segments[0] != "-" || segments[1] != "package" || segments[3] != "dist-tags" {
		registry.recordUnexpected(request)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	packageName, err := url.PathUnescape(segments[2])
	if err != nil || !strings.HasPrefix(packageName, npmScope+"/") {
		registry.recordUnexpected(request)
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	registry.mu.Lock()
	packageData := registry.packages[packageName]
	if packageData == nil {
		registry.mu.Unlock()
		registry.writeJSON(writer, http.StatusNotFound, map[string]string{"error": "package not found"})
		return
	}
	tags := make(map[string]string, len(packageData.distTags))
	for tag, version := range packageData.distTags {
		tags[tag] = version
	}
	registry.mu.Unlock()
	registry.writeJSON(writer, http.StatusOK, tags)
}

func (registry *npmRegistryFixture) tarballURL(name, version string) string {
	parts := strings.SplitN(name, "/", 2)
	return registry.URL + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/-/" + parts[1] + "-" + version + ".tgz"
}

func (registry *npmRegistryFixture) recordUnexpected(request *http.Request) {
	registry.mu.Lock()
	registry.unexpectedRequests = append(registry.unexpectedRequests, request.Method+" "+request.URL.EscapedPath())
	registry.mu.Unlock()
}

func (registry *npmRegistryFixture) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func validateNPMArchive(expectedName string, data []byte) error {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer reader.Close()
	archiveReader := tar.NewReader(io.LimitReader(reader, maxRequestSize))
	manifestFound := false
	for {
		header, err := archiveReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if header.Name != "package/package.json" {
			continue
		}
		manifestBytes, err := io.ReadAll(io.LimitReader(archiveReader, 1<<20))
		if err != nil {
			return err
		}
		var manifest struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
			return err
		}
		if manifest.Name != expectedName {
			return fmt.Errorf("archive package identity %q differs from %q", manifest.Name, expectedName)
		}
		manifestFound = true
	}
	if !manifestFound {
		return errors.New("npm tarball is missing package/package.json")
	}
	return nil
}

func writeNPMUserConfig(t *testing.T, root, registryURL, token string) string {
	t.Helper()
	parsed, err := url.Parse(registryURL)
	if err != nil {
		t.Fatal("parse local npm registry URL:", err)
	}
	configuration := fmt.Sprintf("registry=%s\n%s:registry=%s\n//%s/:_authToken=%s\nalways-auth=true\n", registryURL, npmScope, registryURL, parsed.Host, token)
	path := filepath.Join(root, "npmrc")
	if err := os.WriteFile(path, []byte(configuration), 0o600); err != nil {
		t.Fatal("write temporary npm user config:", err)
	}
	return path
}

func npmEnvironment(root, userConfig, binDirectory string) []string {
	return []string{
		"HOME=" + os.Getenv("HOME"),
		"PATH=" + binDirectory + string(os.PathListSeparator) + os.Getenv("PATH"),
		"npm_config_userconfig=" + userConfig,
		"npm_config_cache=" + filepath.Join(root, "npm-cache"),
		"npm_config_audit=false",
		"npm_config_fund=false",
		"npm_config_update_notifier=false",
		"npm_config_loglevel=error",
		"HTTP_PROXY=http://127.0.0.1:9",
		"HTTPS_PROXY=http://127.0.0.1:9",
		"http_proxy=http://127.0.0.1:9",
		"https_proxy=http://127.0.0.1:9",
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
	}
}

func writeNPMFixturePackage(t *testing.T, root, name, source string, dependencies map[string]string) string {
	t.Helper()
	slash := strings.LastIndex(name, "/")
	packageBase := name[slash+1:]
	project := filepath.Join(root, "publish", packageBase)
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal("create npm package directory:", err)
	}
	manifest := map[string]any{
		"name":        name,
		"version":     npmTestVersion,
		"description": "Synthetic private registry integration fixture",
		"main":        "index.js",
		"exports":     map[string]string{".": "./index.js"},
		"types":       "index.d.ts",
	}
	if dependencies != nil {
		manifest["dependencies"] = dependencies
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal("encode npm package manifest:", err)
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), append(manifestJSON, '\n'), 0o600); err != nil {
		t.Fatal("write npm package manifest:", err)
	}
	if err := os.WriteFile(filepath.Join(project, "index.js"), []byte(source), 0o600); err != nil {
		t.Fatal("write npm package source:", err)
	}
	if err := os.WriteFile(filepath.Join(project, "index.d.ts"), []byte("declare function value(): string;\nexport = value;\n"), 0o600); err != nil {
		t.Fatal("write npm package types:", err)
	}
	return project
}

func writeNPMConsumer(t *testing.T, root string) string {
	t.Helper()
	project := filepath.Join(root, "consumer")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal("create npm consumer directory:", err)
	}
	manifest := map[string]any{
		"name":         "private-registry-fixture-consumer",
		"version":      "0.0.1",
		"private":      true,
		"type":         "commonjs",
		"dependencies": map[string]string{npmParentName: "1.0.0"},
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal("encode npm consumer manifest:", err)
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), append(manifestJSON, '\n'), 0o600); err != nil {
		t.Fatal("write npm consumer manifest:", err)
	}
	return project
}

func runNPM(t *testing.T, npmPath, directory string, environment []string, args ...string) string {
	t.Helper()
	return runCommand(t, npmPath, directory, environment, args...)
}

func runCommand(t *testing.T, executable, directory string, environment []string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir = directory
	command.Env = environment
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", filepath.Base(executable), strings.Join(args, " "), err, output)
	}
	return string(output)
}

func runVersion(t *testing.T, executable string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", filepath.Base(executable), strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}
