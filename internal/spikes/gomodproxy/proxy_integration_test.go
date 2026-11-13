//go:build integration

package gomodproxy

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	parentModule     = "example.com/private/parent/v2"
	leafModule       = "example.com/private/leaf"
	uppercaseModule  = "example.com/private/Upper"
	latestOnlyModule = "example.com/private/latest-only"
)

type proxyObject struct {
	contentType string
	body        []byte
}

type moduleProxy struct {
	objects         map[string]proxyObject
	allowedNotFound map[string]struct{}
	mu              sync.Mutex
	requests        []string
	unexpected      []string
}

func TestGoClientDownloadsPrivateTransitiveModuleV2(t *testing.T) {
	proxy := newModuleProxy(t)
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)

	home := t.TempDir()
	t.Cleanup(func() {
		if err := makeTreeWritable(home); err != nil {
			t.Errorf("make isolated Go cache removable: %v", err)
		}
		if err := os.RemoveAll(home); err != nil {
			t.Errorf("remove isolated Go client state: %v", err)
		}
	})
	workDir := filepath.Join(home, "consumer")
	if err := os.Mkdir(workDir, 0o700); err != nil {
		t.Fatal("create isolated Go consumer directory:", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "go.mod"), []byte(
		"module example.com/private/consumer\n\ngo 1.26.0\n\nrequire "+parentModule+" v2.0.0\n",
	), 0o600); err != nil {
		t.Fatal("write isolated Go consumer module:", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "main.go"), []byte(
		"package main\n\nimport (\"fmt\"; \"example.com/private/parent/v2\")\n\nfunc main() { fmt.Println(parent.Value()) }\n",
	), 0o600); err != nil {
		t.Fatal("write isolated Go consumer source:", err)
	}

	goEnv := isolatedGoEnvironment(home, server.URL)
	runGoCommand(t, workDir, goEnv, "mod", "tidy")
	runGoCommand(t, workDir, goEnv, "mod", "download", "all")
	output := runGoCommand(t, workDir, goEnv, "run", ".")
	if strings.TrimSpace(output) != "parent-v2.0.0/leaf-v1.0.0/uppercase-v1.0.0" {
		t.Fatalf("unexpected transitive module result: %q", strings.TrimSpace(output))
	}

	versions := runGoCommand(t, workDir, goEnv, "list", "-m", "-versions", parentModule)
	if !strings.Contains(versions, "v2.0.0") || !strings.Contains(versions, "v2.1.0") {
		t.Fatalf("Go client did not receive the module version list: %q", versions)
	}
	runGoCommand(t, workDir, goEnv, "get", parentModule+"@latest")
	output = runGoCommand(t, workDir, goEnv, "run", ".")
	if strings.TrimSpace(output) != "parent-v2.1.0/leaf-v1.0.0/uppercase-v1.0.0" {
		t.Fatalf("Go client did not update to the latest v2 release: %q", strings.TrimSpace(output))
	}
	latest := runGoCommand(t, workDir, goEnv, "list", "-m", "-json", latestOnlyModule+"@latest")
	if !strings.Contains(latest, `"Version": "v1.0.0"`) {
		t.Fatalf("Go client did not resolve a module through the @latest endpoint: %q", latest)
	}

	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if len(proxy.unexpected) != 0 {
		t.Fatalf("Go client requested unsupported proxy paths: %v", proxy.unexpected)
	}
	for _, expected := range []string{
		"/" + parentModule + "/@v/list",
		"/" + parentModule + "/@v/v2.0.0.info",
		"/" + parentModule + "/@v/v2.0.0.mod",
		"/" + parentModule + "/@v/v2.0.0.zip",
		"/" + parentModule + "/@v/v2.1.0.info",
		"/" + parentModule + "/@v/v2.1.0.mod",
		"/" + parentModule + "/@v/v2.1.0.zip",
		"/" + leafModule + "/@v/v1.0.0.info",
		"/" + leafModule + "/@v/v1.0.0.mod",
		"/" + leafModule + "/@v/v1.0.0.zip",
		"/" + escapeModulePath(uppercaseModule) + "/@v/v1.0.0.info",
		"/" + escapeModulePath(uppercaseModule) + "/@v/v1.0.0.mod",
		"/" + escapeModulePath(uppercaseModule) + "/@v/v1.0.0.zip",
		"/" + escapeModulePath(uppercaseModule) + "/@v/list",
		"/" + latestOnlyModule + "/@latest",
	} {
		if !contains(proxy.requests, expected) {
			t.Errorf("Go client did not request %s; observed %v", expected, proxy.requests)
		}
	}
}

func newModuleProxy(t *testing.T) *moduleProxy {
	t.Helper()
	proxy := &moduleProxy{
		objects:         make(map[string]proxyObject),
		allowedNotFound: make(map[string]struct{}),
	}
	versions := []string{"v2.0.0", "v2.1.0"}
	for _, version := range versions {
		parentGoMod := "module " + parentModule + "\n\ngo 1.26.0\n\nrequire (\n\t" + leafModule + " v1.0.0\n\t" + uppercaseModule + " v1.0.0\n)\n"
		parentSource := "package parent\n\nimport (\n\t\"" + leafModule + "\"\n\tupper \"" + uppercaseModule + "\"\n)\n\nfunc Value() string { return \"parent-" + version + "/\" + leaf.Value() + \"/\" + upper.Value() }\n"
		if err := proxy.addModule(parentModule, version, parentGoMod, map[string]string{"value.go": parentSource}); err != nil {
			t.Fatal("build parent module proxy objects:", err)
		}
	}
	leafGoMod := "module " + leafModule + "\n\ngo 1.26.0\n"
	leafSource := "package leaf\n\nfunc Value() string { return \"leaf-v1.0.0\" }\n"
	if err := proxy.addModule(leafModule, "v1.0.0", leafGoMod, map[string]string{"value.go": leafSource}); err != nil {
		t.Fatal("build leaf module proxy objects:", err)
	}
	uppercaseGoMod := "module " + uppercaseModule + "\n\ngo 1.26.0\n"
	uppercaseSource := "package upper\n\nfunc Value() string { return \"uppercase-v1.0.0\" }\n"
	if err := proxy.addModule(uppercaseModule, "v1.0.0", uppercaseGoMod, map[string]string{"value.go": uppercaseSource}); err != nil {
		t.Fatal("build uppercase module proxy objects:", err)
	}

	proxy.objects["/"+parentModule+"/@v/list"] = proxyObject{contentType: "text/plain; charset=utf-8", body: []byte(strings.Join(versions, "\n") + "\n")}
	proxy.objects["/"+escapeModulePath(uppercaseModule)+"/@v/list"] = proxyObject{
		contentType: "text/plain; charset=utf-8",
		body:        []byte("v1.0.0\n"),
	}
	proxy.objects["/"+latestOnlyModule+"/@latest"] = jsonObject(map[string]string{
		"Version": "v1.0.0",
		"Time":    "2026-10-12T00:00:00Z",
	})
	proxy.objects["/"+latestOnlyModule+"/@v/list"] = proxyObject{
		contentType: "text/plain; charset=utf-8",
		body:        []byte(""),
	}
	proxy.objects["/"+latestOnlyModule+"/@v/v1.0.0.mod"] = proxyObject{
		contentType: "text/plain; charset=utf-8",
		body:        []byte("module " + latestOnlyModule + "\n\ngo 1.26.0\n"),
	}
	for _, path := range []string{
		"/example.com/@v/list",
		"/example.com/private/@v/list",
		"/example.com/private/parent/@v/list",
		"/example.com/private/leaf/@v/list",
	} {
		proxy.allowedNotFound[path] = struct{}{}
	}
	return proxy
}

func (proxy *moduleProxy) addModule(modulePath, version, goMod string, files map[string]string) error {
	base := "/" + escapeModulePath(modulePath) + "/@v/" + version
	proxy.objects[base+".info"] = jsonObject(map[string]string{
		"Version": version,
		"Time":    "2026-10-12T00:00:00Z",
	})
	proxy.objects[base+".mod"] = proxyObject{contentType: "text/plain; charset=utf-8", body: []byte(goMod)}
	archive, err := moduleArchive(modulePath, version, goMod, files)
	if err != nil {
		return err
	}
	proxy.objects[base+".zip"] = proxyObject{contentType: "application/zip", body: archive}
	return nil
}

func moduleArchive(modulePath, version, goMod string, files map[string]string) ([]byte, error) {
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	root := modulePath + "@" + version + "/"
	contents := make(map[string]string, len(files)+1)
	contents["go.mod"] = goMod
	for path, content := range files {
		contents[path] = content
	}
	paths := make([]string, 0, len(contents))
	for path := range contents {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		entry, err := writer.Create(root + path)
		if err != nil {
			_ = writer.Close()
			return nil, err
		}
		if _, err := io.WriteString(entry, contents[path]); err != nil {
			_ = writer.Close()
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func escapeModulePath(modulePath string) string {
	var escaped strings.Builder
	for _, character := range modulePath {
		if character >= 'A' && character <= 'Z' {
			escaped.WriteByte('!')
			escaped.WriteRune(character + ('a' - 'A'))
			continue
		}
		escaped.WriteRune(character)
	}
	return escaped.String()
}

func jsonObject(value any) proxyObject {
	body, err := json.Marshal(value)
	if err != nil {
		panic("marshal static module proxy metadata: " + err.Error())
	}
	return proxyObject{contentType: "application/json", body: body}
}

func (proxy *moduleProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	proxy.mu.Lock()
	proxy.requests = append(proxy.requests, request.URL.Path)
	if request.Header.Get("Authorization") != "" {
		proxy.unexpected = append(proxy.unexpected, "authorization header sent to local fixture")
	}
	object, found := proxy.objects[request.URL.Path]
	if !found {
		if _, allowed := proxy.allowedNotFound[request.URL.Path]; !allowed {
			proxy.unexpected = append(proxy.unexpected, request.URL.Path)
		}
	}
	proxy.mu.Unlock()

	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !found {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Type", object.contentType)
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(object.body)))
	if request.Method == http.MethodGet {
		_, _ = writer.Write(object.body)
	}
}

func isolatedGoEnvironment(home, proxyURL string) []string {
	cacheDir := filepath.Join(home, "go-cache")
	moduleCache := filepath.Join(home, "go-mod-cache")
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"TMPDIR=" + home,
		"GOMAXPROCS=4",
		"GOCACHE=" + cacheDir,
		"GOMODCACHE=" + moduleCache,
		"GOPATH=" + filepath.Join(home, "gopath"),
		"GOENV=off",
		"GO111MODULE=on",
		"GOTOOLCHAIN=local",
		"GOTELEMETRY=off",
		"GOWORK=off",
		"GOPROXY=" + proxyURL,
		"GOPRIVATE=example.com/private",
		"GONOPROXY=none",
		"GONOSUMDB=example.com/private",
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
	}
}

func runGoCommand(t *testing.T, workDir string, environment []string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir = workDir
	command.Env = environment
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func makeTreeWritable(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o700)
		}
		return nil
	})
}
