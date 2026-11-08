//go:build integration

package hexregistry

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fixtureRepository = "reg-fixture"
const fixtureUsername = "fixture-user"
const fixturePassword = "fixture-password"

func TestMixConsumesAuthenticatedSignedPrivateRegistryAndRejectsTamperedMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("requires the pinned local Mix/Hex client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	root := t.TempDir()
	clientInfo := runMix(t, ctx, root, "", "hex.info")
	for _, expected := range []string{"Hex:    2.5.1", "Elixir: 1.19.5", "OTP:    28.4"} {
		if !strings.Contains(string(clientInfo), expected) {
			t.Fatalf("unsupported Mix/Hex integration baseline; expected %q in %s", expected, clientInfo)
		}
	}
	registryDirectory := filepath.Join(root, "registry")
	publicDirectory := filepath.Join(registryDirectory, "public")
	tarballDirectory := filepath.Join(publicDirectory, "tarballs")
	if err := os.MkdirAll(tarballDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKeyPath := filepath.Join(registryDirectory, "registry-private-key.pem")
	writeRegistryPrivateKey(t, privateKeyPath)

	leafTarball := buildFixturePackage(t, ctx, root, "registry_fixture_leaf", "0.1.0", `defmodule RegistryFixtureLeaf do
	def value, do: "private-leaf-value"
end
	`, "")
	parentTarball := buildFixturePackage(t, ctx, root, "registry_fixture_parent", "0.1.0", `defmodule RegistryFixtureParent do
	def value, do: RegistryFixtureLeaf.value()
end
`, `{:registry_fixture_leaf, "~> 0.1.0", repo: "reg-fixture"}`)
	copyFixtureTarball(t, leafTarball, filepath.Join(tarballDirectory, filepath.Base(leafTarball)))
	copyFixtureTarball(t, parentTarball, filepath.Join(tarballDirectory, filepath.Base(parentTarball)))
	runMix(t, ctx, registryDirectory, "", "hex.registry", "build", "public", "--name="+fixtureRepository, "--private-key="+privateKeyPath)
	publicKeyPath := filepath.Join(publicDirectory, "public_key")
	if info, err := os.Stat(publicKeyPath); err != nil || !info.Mode().IsRegular() {
		t.Fatal("Mix did not create the public registry trust key", err)
	}
	parentMetadataPath := filepath.Join(publicDirectory, "packages", "registry_fixture_parent")
	if info, err := os.Stat(parentMetadataPath); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatal("Mix did not create signed parent package metadata", err)
	}

	server := startAuthenticatedRegistryServer(t, publicDirectory)
	clientProject := filepath.Join(root, "client-valid")
	writeClientProject(t, clientProject)
	hexHome := filepath.Join(root, "hex-home-valid")
	configureHexRepository(t, ctx, clientProject, hexHome, server.URL, publicKeyPath)
	if output, err := runMixExpectedFailure(t, ctx, clientProject, hexHome, "deps.get"); err != nil {
		t.Fatalf("valid signed private registry dependency resolution failed: %v\n%s\nrequests: %v", err, output, server.paths())
	}
	output := runMix(t, ctx, clientProject, hexHome, "run", "-e", "IO.puts(RegistryFixtureParent.value())")
	if !strings.Contains(string(output), "private-leaf-value") {
		t.Fatalf("Mix did not compile/resolve the private transitive package: %s", output)
	}
	if server.authenticatedRequests.Load() == 0 {
		t.Fatal("Mix did not authenticate any private repository request")
	}

	if err := tamperSignedGzipResource(parentMetadataPath); err != nil {
		t.Fatal(err)
	}
	requestOffset := len(server.paths())
	authenticatedOffset := server.authenticatedRequests.Load()
	clientProjectTampered := filepath.Join(root, "client-tampered")
	writeClientProject(t, clientProjectTampered)
	tamperedHexHome := filepath.Join(root, "hex-home-tampered")
	configureHexRepository(t, ctx, clientProjectTampered, tamperedHexHome, server.URL, publicKeyPath)
	tamperedOutput, tamperedErr := runMixExpectedFailure(t, ctx, clientProjectTampered, tamperedHexHome, "deps.get")
	if tamperedErr == nil {
		t.Fatalf("Mix accepted tampered signed package metadata: %s", tamperedOutput)
	}
	if !strings.Contains(strings.ToLower(string(tamperedOutput)), "signature") {
		t.Fatalf("Mix failed for a reason other than signed-metadata rejection: %s", tamperedOutput)
	}
	tamperedPaths := server.paths()[requestOffset:]
	if !containsString(tamperedPaths, "GET /packages/registry_fixture_parent") {
		t.Fatalf("tampered metadata was not fetched during the negative test: %v", tamperedPaths)
	}
	if server.authenticatedRequests.Load() <= authenticatedOffset {
		t.Fatal("tampered metadata was not served to the authenticated client")
	}
	t.Logf("Mix/Hex authenticated repository: successful transitive resolution; tampered package metadata rejected")
}

type authenticatedRegistryServer struct {
	URL                   string
	authenticatedRequests atomic.Int64
	mu                    sync.Mutex
	requestedPaths        []string
}

func startAuthenticatedRegistryServer(t *testing.T, publicDirectory string) *authenticatedRegistryServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverState := &authenticatedRegistryServer{URL: "http://" + listener.Addr().String()}
	files := http.FileServer(http.Dir(publicDirectory))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		serverState.mu.Lock()
		serverState.requestedPaths = append(serverState.requestedPaths, request.Method+" "+request.URL.Path)
		serverState.mu.Unlock()
		username, password, ok := request.BasicAuth()
		if !ok || username != fixtureUsername || password != fixturePassword {
			writer.Header().Set("WWW-Authenticate", `Basic realm="private Hex fixture"`)
			http.Error(writer, "authentication required", http.StatusUnauthorized)
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		serverState.authenticatedRequests.Add(1)
		files.ServeHTTP(writer, request)
	}))
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	return serverState
}

func (server *authenticatedRegistryServer) paths() []string {
	server.mu.Lock()
	defer server.mu.Unlock()
	return append([]string(nil), server.requestedPaths...)
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func writeRegistryPrivateKey(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func buildFixturePackage(t *testing.T, ctx context.Context, root, name, version, source, dependencies string) string {
	t.Helper()
	projectDirectory := filepath.Join(root, "packages", name)
	if err := os.MkdirAll(filepath.Join(projectDirectory, "lib"), 0o700); err != nil {
		t.Fatal(err)
	}
	mixProject := fmt.Sprintf(`defmodule %s.MixProject do
  use Mix.Project

  def project do
    [
      app: :%s,
      version: "%s",
      elixir: ">= 1.14.0",
      deps: [%s],
      description: "Synthetic private registry integration fixture",
      package: [files: ["lib", "mix.exs"], licenses: ["MIT"], links: %%{}]
    ]
  end

  def application, do: [extra_applications: [:logger]]
end
`, mixModuleName(name), name, version, strings.TrimSpace(dependencies))
	if err := os.WriteFile(filepath.Join(projectDirectory, "mix.exs"), []byte(mixProject), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDirectory, "lib", name+".ex"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	tarball := filepath.Join(root, "tarballs", name+"-"+version+".tar")
	if err := os.MkdirAll(filepath.Dir(tarball), 0o700); err != nil {
		t.Fatal(err)
	}
	runMix(t, ctx, projectDirectory, "", "hex.build", "--output", tarball)
	return tarball
}

func mixModuleName(packageName string) string {
	parts := strings.Split(packageName, "_")
	for index := range parts {
		if len(parts[index]) > 0 {
			parts[index] = strings.ToUpper(parts[index][:1]) + parts[index][1:]
		}
	}
	return strings.Join(parts, "")
}

func copyFixtureTarball(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func tamperSignedGzipResource(path string) error {
	compressed, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return err
	}
	signed, readErr := io.ReadAll(io.LimitReader(reader, 1<<20))
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	if len(signed) == 1<<20 {
		return errors.New("signed registry resource exceeds the fixture limit")
	}
	if len(signed) < 8 {
		return fmt.Errorf("signed registry resource too short: %d bytes", len(signed))
	}
	signed[len(signed)-1] ^= 0x01
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(signed); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, output.Bytes(), 0o600)
}

func writeClientProject(t *testing.T, directory string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	content := `defmodule RegistryFixtureClient.MixProject do
  use Mix.Project

  def project do
    [app: :registry_fixture_client, version: "0.1.0", elixir: ">= 1.14.0", deps: deps()]
  end

  def application, do: [extra_applications: [:logger]]

  defp deps do
    [{:registry_fixture_parent, "~> 0.1.0", repo: "reg-fixture"}]
  end
end
`
	if err := os.WriteFile(filepath.Join(directory, "mix.exs"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func configureHexRepository(t *testing.T, ctx context.Context, projectDirectory, hexHome, repositoryURL, publicKeyPath string) {
	t.Helper()
	if err := os.MkdirAll(hexHome, 0o700); err != nil {
		t.Fatal(err)
	}
	runMix(t, ctx, projectDirectory, hexHome, "hex.repo", "add", fixtureRepository,
		strings.Replace(repositoryURL, "http://", "http://"+fixtureUsername+":"+fixturePassword+"@", 1), "--public-key="+publicKeyPath)
}

func runMix(t *testing.T, ctx context.Context, directory, hexHome string, args ...string) []byte {
	t.Helper()
	output, err := runMixExpectedFailure(t, ctx, directory, hexHome, args...)
	if err != nil {
		t.Fatalf("mix %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}

func runMixExpectedFailure(t *testing.T, ctx context.Context, directory, hexHome string, args ...string) ([]byte, error) {
	t.Helper()
	command := exec.CommandContext(ctx, "mix", args...)
	command.Dir = directory
	command.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"HEX_HOME=" + hexHome,
		"HEX_OFFLINE=false",
		"HEX_UNSAFE_REGISTRY=false",
		"HEX_NO_VERIFY_REPO_ORIGIN=false",
		"HEX_HTTP_CONCURRENCY=2",
		"HEX_HTTP_TIMEOUT=2",
		"HEX_API_URL=http://127.0.0.1:1",
		"HTTP_PROXY=",
		"HTTPS_PROXY=",
		"http_proxy=",
		"https_proxy=",
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
		"ERL_FLAGS=+S 2:2 +SDcpu 1:1 +SDio 1 +A 2",
		"ELIXIR_ERL_OPTIONS=+fnu",
	}
	if mixHome := os.Getenv("MIX_HOME"); mixHome != "" {
		command.Env = append(command.Env, "MIX_HOME="+mixHome)
	}
	if mixArchives := os.Getenv("MIX_ARCHIVES"); mixArchives != "" {
		command.Env = append(command.Env, "MIX_ARCHIVES="+mixArchives)
	}
	return command.CombinedOutput()
}
