//go:build integration

package pubregistry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	dartVersion           = "3.13.5"
	leafPackageName       = "registry_fixture_leaf"
	parentPackageName     = "registry_fixture_parent"
	packageVersion        = "1.0.0"
	pubTokenEnvironment   = "PRIVATE_REGISTRY_PUB_FIXTURE_TOKEN"
	maxPackageArchiveSize = 8 << 20
)

type pendingUpload struct {
	archive []byte
}

type publishedPackage struct {
	name       string
	version    string
	pubspec    map[string]any
	archive    []byte
	archiveSHA string
}

type registryFixture struct {
	URL               string
	Token             string
	server            *httptest.Server
	mu                sync.Mutex
	pending           map[string]*pendingUpload
	packages          map[string]map[string]*publishedPackage
	unauthorizedPaths []string
	unexpectedPaths   []string
	publicationStarts int
	uploads           int
	finalizations     int
	metadataReads     int
	archiveReads      int
}

func TestDartPubPublishesAndConsumesAuthenticatedPrivatePackages(t *testing.T) {
	dartPath := requiredDartBinary(t)
	if output := runDartVersion(t, dartPath); !strings.Contains(output, "Dart SDK version: "+dartVersion) {
		t.Fatalf("unsupported Dart integration baseline %q; expected %s", output, dartVersion)
	}

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal("restrict Pub fixture directory:", err)
	}
	registry := startRegistry(t)
	configHome := filepath.Join(root, "config")
	environment := pubEnvironment(t, root, configHome)

	consumer := writeConsumer(t, root, registry.URL)
	output, err := runDart(t, dartPath, consumer, environment, "pub", "get")
	if err == nil || !strings.Contains(output, "synthetic registry token required") {
		t.Fatalf("Pub without a token should fail with the registry challenge; err=%v output=%s", err, output)
	}

	wrongToken := "synthetic-invalid-token"
	wrongEnvironment := appendEnvironment(environment, pubTokenEnvironment, wrongToken)
	runDartMustSucceed(t, dartPath, root, wrongEnvironment, "pub", "token", "add", "--env-var="+pubTokenEnvironment, registry.URL)
	output, err = runDart(t, dartPath, consumer, wrongEnvironment, "pub", "get")
	if err == nil || !strings.Contains(output, "synthetic registry token required") {
		t.Fatalf("Pub with an invalid token should reject it; err=%v output=%s", err, redact(output, wrongToken))
	}
	assertPubTokenReferenceRemoved(t, configHome, wrongToken)

	secret, err := randomPubToken()
	if err != nil {
		t.Fatal("generate synthetic Pub token:", err)
	}
	registry.mu.Lock()
	registry.Token = secret
	registry.mu.Unlock()
	authenticatedEnvironment := appendEnvironment(environment, pubTokenEnvironment, secret)
	runDartMustSucceed(t, dartPath, root, authenticatedEnvironment, "pub", "token", "add", "--env-var="+pubTokenEnvironment, registry.URL)

	for _, name := range []string{leafPackageName, parentPackageName} {
		packageDirectory := writePublishPackage(t, root, registry.URL, name)
		runDartMustSucceed(t, dartPath, packageDirectory, authenticatedEnvironment, "pub", "publish", "--force")
	}
	runDartMustSucceed(t, dartPath, consumer, authenticatedEnvironment, "pub", "get")
	if _, err := os.Stat(filepath.Join(consumer, "pubspec.lock")); err != nil {
		t.Fatalf("Dart Pub did not write a lockfile: %v", err)
	}
	output, err = runDart(t, dartPath, consumer, authenticatedEnvironment, "run", "bin/main.dart")
	if err != nil {
		t.Fatalf("run Pub consumer: %v\n%s", err, redact(output, secret))
	}
	if strings.TrimSpace(output) != "parent/private-leaf-value" {
		t.Fatalf("Pub did not install the transitive private package: %q", strings.TrimSpace(output))
	}

	assertPubTokenReferenceStored(t, configHome, secret)
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.publicationStarts != 2 || registry.uploads != 2 || registry.finalizations != 2 {
		t.Errorf("Pub publication flow counts start/upload/finalize = %d/%d/%d; want 2/2/2", registry.publicationStarts, registry.uploads, registry.finalizations)
	}
	if registry.metadataReads < 4 || registry.archiveReads < 2 {
		t.Errorf("expected package metadata and archive reads; metadata=%d archives=%d", registry.metadataReads, registry.archiveReads)
	}
	if len(registry.unauthorizedPaths) != 2 {
		t.Errorf("unauthorized request paths = %v; want missing-token and invalid-token requests", registry.unauthorizedPaths)
	}
	if len(registry.unexpectedPaths) != 0 {
		t.Errorf("Pub requested unsupported routes: %v", registry.unexpectedPaths)
	}
}

func startRegistry(t *testing.T) *registryFixture {
	t.Helper()
	token, err := randomPubToken()
	if err != nil {
		t.Fatal("generate initial synthetic Pub token:", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen for Pub registry fixture:", err)
	}
	registry := &registryFixture{
		Token:    token,
		pending:  make(map[string]*pendingUpload),
		packages: make(map[string]map[string]*publishedPackage),
	}
	server := httptest.NewUnstartedServer(registry)
	server.Listener = listener
	server.Start()
	registry.server = server
	// Pub permits HTTP credentials for localhost; all fixture data and tokens are synthetic.
	registry.URL = strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
	t.Cleanup(server.Close)
	return registry
}

func (registry *registryFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if !registry.authorized(writer, request) {
		return
	}
	if request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/api/packages/") && (!strings.HasPrefix(request.URL.Path, "/api/packages/versions/") || request.URL.Path == "/api/packages/versions/new") {
		if !strings.Contains(request.Header.Get("Accept"), "application/vnd.pub.v2+json") {
			registry.recordUnexpected(request)
			registry.writeError(writer, http.StatusNotAcceptable, "UNSUPPORTED_API_VERSION", "Pub API v2 must be requested")
			return
		}
		if !strings.HasPrefix(request.Header.Get("User-Agent"), "Dart pub ") {
			registry.recordUnexpected(request)
			registry.writeError(writer, http.StatusBadRequest, "MISSING_USER_AGENT", "Dart Pub user agent is required")
			return
		}
	}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/api/packages/versions/new":
		registry.serveStartPublication(writer)
	case request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, "/api/uploads/"):
		registry.serveUpload(writer, request)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/api/finalize/"):
		registry.serveFinalize(writer, request)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/api/packages/"):
		registry.servePackageMetadata(writer, request)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/packages/"):
		registry.servePackageArchive(writer, request)
	default:
		registry.mu.Lock()
		registry.unexpectedPaths = append(registry.unexpectedPaths, request.Method+" "+request.URL.EscapedPath())
		registry.mu.Unlock()
		registry.writeError(writer, http.StatusNotFound, "NOT_FOUND", "fixture route not found")
	}
}

func (registry *registryFixture) authorized(writer http.ResponseWriter, request *http.Request) bool {
	registry.mu.Lock()
	token := registry.Token
	registry.mu.Unlock()
	if request.Header.Get("Authorization") == "Bearer "+token {
		return true
	}
	registry.mu.Lock()
	registry.unauthorizedPaths = append(registry.unauthorizedPaths, request.Method+" "+request.URL.EscapedPath())
	registry.mu.Unlock()
	writer.Header().Set("WWW-Authenticate", `Bearer realm="pub", message="synthetic registry token required"`)
	registry.writeError(writer, http.StatusUnauthorized, "AUTH_REQUIRED", "synthetic registry token required")
	return false
}

func (registry *registryFixture) serveStartPublication(writer http.ResponseWriter) {
	identifier, err := randomPubToken()
	if err != nil {
		registry.writeError(writer, http.StatusInternalServerError, "INTERNAL", "could not allocate fixture upload")
		return
	}
	uploadID := identifier[:24]
	registry.mu.Lock()
	registry.pending[uploadID] = &pendingUpload{}
	registry.publicationStarts++
	registry.mu.Unlock()
	registry.writeJSON(writer, http.StatusOK, map[string]any{
		"url":    registry.URL + "/api/uploads/" + uploadID,
		"fields": map[string]string{"upload_id": uploadID},
	})
}

func (registry *registryFixture) serveUpload(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxPackageArchiveSize+1<<20)
	if err := request.ParseMultipartForm(maxPackageArchiveSize); err != nil {
		registry.writeError(writer, http.StatusBadRequest, "INVALID_UPLOAD", "malformed package upload")
		return
	}
	if request.MultipartForm != nil {
		defer request.MultipartForm.RemoveAll()
	}
	uploadID := strings.TrimPrefix(request.URL.Path, "/api/uploads/")
	if request.FormValue("upload_id") != uploadID {
		registry.writeError(writer, http.StatusBadRequest, "INVALID_UPLOAD", "upload id does not match")
		return
	}
	archiveFile, _, err := request.FormFile("file")
	if err != nil {
		registry.writeError(writer, http.StatusBadRequest, "INVALID_UPLOAD", "package archive is required")
		return
	}
	defer archiveFile.Close()
	archive, err := io.ReadAll(io.LimitReader(archiveFile, maxPackageArchiveSize+1))
	if err != nil || len(archive) == 0 || len(archive) > maxPackageArchiveSize {
		registry.writeError(writer, http.StatusRequestEntityTooLarge, "ARCHIVE_TOO_LARGE", "package archive exceeds fixture limits")
		return
	}
	registry.mu.Lock()
	pending := registry.pending[uploadID]
	if pending != nil {
		pending.archive = append([]byte(nil), archive...)
		registry.uploads++
	}
	registry.mu.Unlock()
	if pending == nil {
		registry.writeError(writer, http.StatusNotFound, "UPLOAD_NOT_FOUND", "upload is no longer available")
		return
	}
	writer.Header().Set("Location", registry.URL+"/api/finalize/"+uploadID)
	writer.WriteHeader(http.StatusNoContent)
}

func (registry *registryFixture) serveFinalize(writer http.ResponseWriter, request *http.Request) {
	uploadID := strings.TrimPrefix(request.URL.Path, "/api/finalize/")
	registry.mu.Lock()
	pending := registry.pending[uploadID]
	var archive []byte
	if pending != nil {
		archive = append([]byte(nil), pending.archive...)
	}
	registry.mu.Unlock()
	if len(archive) == 0 {
		registry.writeError(writer, http.StatusNotFound, "UPLOAD_NOT_FOUND", "uploaded package is unavailable")
		return
	}
	name, version, manifest, err := inspectPubArchive(archive)
	if err != nil {
		registry.writeError(writer, http.StatusBadRequest, "INVALID_PACKAGE", "package archive failed fixture validation")
		return
	}
	checksum := sha256.Sum256(archive)
	packageData := &publishedPackage{
		name:       name,
		version:    version,
		pubspec:    pubspecMetadata(name, version, manifest, registry.URL),
		archive:    archive,
		archiveSHA: hex.EncodeToString(checksum[:]),
	}
	registry.mu.Lock()
	if registry.packages[name] == nil {
		registry.packages[name] = make(map[string]*publishedPackage)
	}
	if registry.packages[name][version] != nil {
		delete(registry.pending, uploadID)
		registry.mu.Unlock()
		registry.writeError(writer, http.StatusConflict, "VERSION_EXISTS", "package version already exists")
		return
	}
	registry.packages[name][version] = packageData
	delete(registry.pending, uploadID)
	registry.finalizations++
	registry.mu.Unlock()
	registry.writeJSON(writer, http.StatusOK, map[string]any{
		"success": map[string]string{"message": "synthetic package publication finalized"},
	})
}

func (registry *registryFixture) servePackageMetadata(writer http.ResponseWriter, request *http.Request) {
	name, err := url.PathUnescape(strings.TrimPrefix(request.URL.Path, "/api/packages/"))
	if err != nil || name == "" || strings.Contains(name, "/") {
		registry.writeError(writer, http.StatusBadRequest, "INVALID_PACKAGE_NAME", "invalid package name")
		return
	}
	registry.mu.Lock()
	registry.metadataReads++
	versionsByName := registry.packages[name]
	versions := make([]*publishedPackage, 0, len(versionsByName))
	for _, packageData := range versionsByName {
		versions = append(versions, packageData)
	}
	registry.mu.Unlock()
	if len(versions) == 0 {
		registry.writeError(writer, http.StatusNotFound, "PACKAGE_NOT_FOUND", "package does not exist")
		return
	}
	sort.Slice(versions, func(first, second int) bool {
		return versions[first].version < versions[second].version
	})
	versionMetadata := make([]map[string]any, 0, len(versions))
	for _, packageData := range versions {
		versionMetadata = append(versionMetadata, registry.versionMetadata(packageData))
	}
	registry.writeJSON(writer, http.StatusOK, map[string]any{
		"name":     name,
		"latest":   versionMetadata[len(versionMetadata)-1],
		"versions": versionMetadata,
	})
}

func (registry *registryFixture) versionMetadata(packageData *publishedPackage) map[string]any {
	return map[string]any{
		"version":        packageData.version,
		"archive_url":    registry.URL + "/packages/" + url.PathEscape(packageData.name) + "/" + url.PathEscape(packageData.version) + ".tar.gz",
		"archive_sha256": packageData.archiveSHA,
		"pubspec":        packageData.pubspec,
	}
}

func (registry *registryFixture) servePackageArchive(writer http.ResponseWriter, request *http.Request) {
	segments := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(segments) != 3 || segments[0] != "packages" {
		registry.recordUnexpected(request)
		registry.writeError(writer, http.StatusNotFound, "NOT_FOUND", "fixture archive route not found")
		return
	}
	name, err := url.PathUnescape(segments[1])
	if err != nil {
		registry.writeError(writer, http.StatusBadRequest, "INVALID_PACKAGE_NAME", "invalid package name")
		return
	}
	version := strings.TrimSuffix(segments[2], ".tar.gz")
	registry.mu.Lock()
	registry.archiveReads++
	packageData := registry.packages[name][version]
	var archive []byte
	if packageData != nil {
		archive = append([]byte(nil), packageData.archive...)
	}
	registry.mu.Unlock()
	if len(archive) == 0 {
		registry.writeError(writer, http.StatusNotFound, "ARCHIVE_NOT_FOUND", "package archive does not exist")
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(archive)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(archive)
}

func (registry *registryFixture) recordUnexpected(request *http.Request) {
	registry.mu.Lock()
	registry.unexpectedPaths = append(registry.unexpectedPaths, request.Method+" "+request.URL.EscapedPath())
	registry.mu.Unlock()
}

func (registry *registryFixture) writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/vnd.pub.v2+json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

func (registry *registryFixture) writeError(writer http.ResponseWriter, status int, code, message string) {
	registry.writeJSON(writer, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func inspectPubArchive(data []byte) (string, string, string, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", "", "", err
	}
	defer reader.Close()
	tarReader := tar.NewReader(io.LimitReader(reader, maxPackageArchiveSize))
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return "", "", "", errors.New("archive has no pubspec.yaml")
		}
		if err != nil {
			return "", "", "", err
		}
		if path.Base(header.Name) != "pubspec.yaml" {
			continue
		}
		manifestBytes, err := io.ReadAll(io.LimitReader(tarReader, 1<<20))
		if err != nil {
			return "", "", "", err
		}
		manifest := string(manifestBytes)
		var name string
		var version string
		for _, line := range strings.Split(manifest, "\n") {
			if strings.HasPrefix(line, "name: ") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "name: "))
			}
			if strings.HasPrefix(line, "version: ") {
				version = strings.TrimSpace(strings.TrimPrefix(line, "version: "))
			}
		}
		if name == "" || version == "" {
			return "", "", "", errors.New("pubspec has no package name or version")
		}
		return name, version, manifest, nil
	}
}

func pubspecMetadata(name, version, manifest, registryURL string) map[string]any {
	metadata := map[string]any{
		"name":        name,
		"version":     version,
		"description": "Synthetic private registry contract package",
		"environment": map[string]any{"sdk": ">=3.0.0 <4.0.0"},
	}
	if name == parentPackageName && strings.Contains(manifest, leafPackageName) {
		metadata["dependencies"] = map[string]any{
			leafPackageName: map[string]any{
				"hosted":  map[string]string{"name": leafPackageName, "url": registryURL},
				"version": "^1.0.0",
			},
		}
	}
	return metadata
}

func requiredDartBinary(t *testing.T) string {
	t.Helper()
	if override := os.Getenv("PUB_TEST_DART_BIN"); override != "" {
		info, err := os.Stat(override)
		if err != nil || info.IsDir() || info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("PUB_TEST_DART_BIN must name an executable Dart binary")
		}
		return override
	}
	binary, err := exec.LookPath("dart")
	if err != nil {
		t.Fatal("Dart SDK is required for the Pub integration contract; set PUB_TEST_DART_BIN if it is not on PATH")
	}
	return binary
}

func runDartVersion(t *testing.T, dartPath string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, dartPath, "--version")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect Dart SDK version: %v\n%s", err, output)
	}
	return strings.TrimSpace(string(output))
}

func runDart(t *testing.T, dartPath, directory string, environment []string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, dartPath, args...)
	command.Dir = directory
	command.Env = environment
	output, err := command.CombinedOutput()
	return string(output), err
}

func runDartMustSucceed(t *testing.T, dartPath, directory string, environment []string, args ...string) string {
	t.Helper()
	output, err := runDart(t, dartPath, directory, environment, args...)
	if err != nil {
		token := environmentValue(environment, pubTokenEnvironment)
		t.Fatalf("dart %s failed: %v\n%s", strings.Join(args, " "), err, redact(output, token))
	}
	return output
}

func pubEnvironment(t *testing.T, root, configHome string) []string {
	t.Helper()
	values := make([]string, 0, 24)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "PATH", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR":
			values = append(values, entry)
		}
	}
	cacheDirectory := filepath.Join(root, "pub-cache")
	for _, directory := range []string{filepath.Join(root, "home"), configHome, cacheDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal("create private Pub test state:", err)
		}
	}
	values = append(values,
		"HOME="+filepath.Join(root, "home"),
		"XDG_CONFIG_HOME="+configHome,
		"PUB_CACHE="+cacheDirectory,
		"PUB_ENVIRONMENT=bot",
		"CI=true",
		"HTTP_PROXY=http://127.0.0.1:9",
		"HTTPS_PROXY=http://127.0.0.1:9",
		"ALL_PROXY=http://127.0.0.1:9",
		"http_proxy=http://127.0.0.1:9",
		"https_proxy=http://127.0.0.1:9",
		"all_proxy=http://127.0.0.1:9",
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
	)
	return values
}

func appendEnvironment(environment []string, key, value string) []string {
	updated := make([]string, 0, len(environment)+1)
	prefix := key + "="
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			updated = append(updated, entry)
		}
	}
	return append(updated, prefix+value)
}

func environmentValue(environment []string, key string) string {
	prefix := key + "="
	for _, entry := range environment {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}

func writePublishPackage(t *testing.T, root, registryURL, name string) string {
	t.Helper()
	packageDirectory := filepath.Join(root, "publish", name)
	if err := os.MkdirAll(filepath.Join(packageDirectory, "lib"), 0o700); err != nil {
		t.Fatal("create synthetic Pub package:", err)
	}
	dependency := ""
	if name == parentPackageName {
		dependency = fmt.Sprintf("\ndependencies:\n  %s:\n    hosted:\n      name: %s\n      url: %s\n    version: ^1.0.0\n", leafPackageName, leafPackageName, registryURL)
	}
	manifest := fmt.Sprintf("name: %s\nversion: %s\npublish_to: %s\ndescription: Synthetic private registry contract package\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\n%s", name, packageVersion, registryURL, dependency)
	writePrivateFile(t, filepath.Join(packageDirectory, "pubspec.yaml"), []byte(manifest))
	writePrivateFile(t, filepath.Join(packageDirectory, "README.md"), []byte("# Synthetic package\n"))
	writePrivateFile(t, filepath.Join(packageDirectory, "CHANGELOG.md"), []byte("## 1.0.0\n\nSynthetic fixture release.\n"))
	writePrivateFile(t, filepath.Join(packageDirectory, "LICENSE"), []byte("Synthetic fixture data; not for redistribution.\n"))
	source := "String fixtureLeafValue() => 'private-leaf-value';\n"
	if name == parentPackageName {
		source = fmt.Sprintf("import 'package:%s/%s.dart';\n\nString fixtureParentValue() => 'parent/\u0024{fixtureLeafValue()}';\n", leafPackageName, leafPackageName)
	}
	writePrivateFile(t, filepath.Join(packageDirectory, "lib", name+".dart"), []byte(source))
	return packageDirectory
}

func writeConsumer(t *testing.T, root, registryURL string) string {
	t.Helper()
	consumerDirectory := filepath.Join(root, "consumer")
	if err := os.MkdirAll(filepath.Join(consumerDirectory, "bin"), 0o700); err != nil {
		t.Fatal("create synthetic Pub consumer:", err)
	}
	manifest := fmt.Sprintf("name: pub_registry_fixture_consumer\npublish_to: none\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\ndependencies:\n  %s:\n    hosted:\n      name: %s\n      url: %s\n    version: ^1.0.0\n", parentPackageName, parentPackageName, registryURL)
	writePrivateFile(t, filepath.Join(consumerDirectory, "pubspec.yaml"), []byte(manifest))
	main := fmt.Sprintf("import 'package:%s/%s.dart';\n\nvoid main() { print(fixtureParentValue()); }\n", parentPackageName, parentPackageName)
	writePrivateFile(t, filepath.Join(consumerDirectory, "bin", "main.dart"), []byte(main))
	return consumerDirectory
}

func writePrivateFile(t *testing.T, filePath string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(filePath, contents, 0o600); err != nil {
		t.Fatal("write synthetic Pub fixture:", err)
	}
}

func randomPubToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func assertPubTokenReferenceRemoved(t *testing.T, configHome, token string) {
	t.Helper()
	path := filepath.Join(configHome, "dart", "pub-tokens.json")
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal("read isolated Pub token configuration:", err)
	}
	if strings.Contains(string(contents), pubTokenEnvironment) || strings.Contains(string(contents), token) {
		t.Fatalf("Pub retained an invalid token reference in its isolated configuration")
	}
}

func assertPubTokenReferenceStored(t *testing.T, configHome, token string) {
	t.Helper()
	path := filepath.Join(configHome, "dart", "pub-tokens.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read isolated Pub token configuration:", err)
	}
	if !strings.Contains(string(contents), pubTokenEnvironment) {
		t.Fatal("Pub did not store an environment-variable reference for the token")
	}
	if strings.Contains(string(contents), token) {
		t.Fatal("Pub stored the resolved token instead of its environment-variable reference")
	}
}

func redact(value, secret string) string {
	if secret == "" {
		return value
	}
	return strings.ReplaceAll(value, secret, "[redacted]")
}
