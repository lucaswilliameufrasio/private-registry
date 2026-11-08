package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/gomod"
	"private-registry/internal/repositories"
	"private-registry/internal/storage"
)

func TestGoProxyPrivateTokenAndTerminalMissingModule(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var owner string
	if err := fixture.db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	workspace, err := fixture.workspaceService.CreateWorkspace(ctx, owner, "go-http", "Go HTTP")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := fixture.repositoryService.CreateWithFormat(ctx, owner, workspace.ID, "modules", "Modules", repositories.FormatGo)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []repositories.GrantRole{repositories.GrantReader, repositories.GrantPublisher} {
		if _, err := fixture.repositoryService.GrantRepositoryRole(ctx, owner, workspace.ID, repo.ID, owner, role); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	objects, err := storage.NewFileSystem(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	modules, err := gomod.NewService(fixture.db, config.SQLite, fixture.repositoryService, objects, gomod.Options{StagingDirectory: staging, MaxZipBytes: 1 << 20, MaxFiles: 100, MaxConcurrent: 2})
	if err != nil {
		t.Fatal(err)
	}
	modulePath, version := "example.com/private/Upper", "v1.0.0"
	mod := []byte("module " + modulePath + "\n\ngo 1.24\n")
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for name, content := range map[string][]byte{"go.mod": mod, "upper.go": []byte("package upper\n")} {
		entry, err := writer.Create(modulePath + "@" + version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := modules.Publish(ctx, owner, workspace.ID, repo.ID, modulePath, version, time.Now(), mod, bytes.NewReader(archive.Bytes())); err != nil {
		t.Fatal(err)
	}
	for _, dependency := range []struct {
		path, version, mod, source string
	}{
		{"example.com/private/leaf", "v1.0.0", "module example.com/private/leaf\n\ngo 1.24\n", "package leaf\nfunc Value() string { return \"private\" }\n"},
		{"example.com/private/parent/v2", "v2.0.0", "module example.com/private/parent/v2\n\ngo 1.24\n\nrequire example.com/private/leaf v1.0.0\n", "package parent\nimport \"example.com/private/leaf\"\nfunc Value() string { return leaf.Value() }\n"},
	} {
		var zipped bytes.Buffer
		zipWriter := zip.NewWriter(&zipped)
		for name, content := range map[string]string{"go.mod": dependency.mod, "module.go": dependency.source} {
			entry, err := zipWriter.Create(dependency.path + "@" + dependency.version + "/" + name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write([]byte(content)); err != nil {
				t.Fatal(err)
			}
		}
		if err := zipWriter.Close(); err != nil {
			t.Fatal(err)
		}
		if err := modules.Publish(ctx, owner, workspace.ID, repo.ID, dependency.path, dependency.version, time.Now(), []byte(dependency.mod), bytes.NewReader(zipped.Bytes())); err != nil {
			t.Fatal(err)
		}
	}
	issued, err := fixture.repositoryService.IssuePersonalReadToken(ctx, owner, workspace.ID, repo.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: authTestOrigin, AssetOrigin: authTestAssetOrigin, GoModules: modules})
	if err != nil {
		t.Fatal(err)
	}
	base := "/go/" + workspace.ID + "/" + repo.ID + "/example.com/private/!upper"
	for _, test := range []struct {
		path        string
		contentType string
		contains    string
	}{
		{base + "/@v/list", "text/plain", "v1.0.0\n"},
		{base + "/@latest", "application/json", `"Version":"v1.0.0"`},
		{base + "/@v/v1.0.0.info", "application/json", `"Version":"v1.0.0"`},
		{base + "/@v/v1.0.0.mod", "text/plain", string(mod)},
		{base + "/@v/v1.0.0.zip", "application/zip", ""},
	} {
		response := authBearerHTTPRequest(handler, http.MethodGet, test.path, "registry.example", "Bearer "+issued.Bearer, "", "")
		if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), test.contentType) || !strings.Contains(response.Body.String(), test.contains) || response.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatalf("proxy route %s status=%d content-type=%q", test.path, response.Code, response.Header().Get("Content-Type"))
		}
		if strings.HasSuffix(test.path, ".zip") && !bytes.Equal(response.Body.Bytes(), archive.Bytes()) {
			t.Fatal("proxy returned different ZIP bytes")
		}
	}
	missing := authBearerHTTPRequest(handler, http.MethodGet, "/go/"+workspace.ID+"/"+repo.ID+"/example.com/private/missing/@v/list", "registry.example", "Bearer "+issued.Bearer, "", "")
	if missing.Code != http.StatusForbidden {
		t.Fatalf("missing private module returned %d, want terminal 403", missing.Code)
	}
	unauthorized := authBearerHTTPRequest(handler, http.MethodGet, base+"/@v/list", "registry.example", "Bearer invalid", "", "")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token returned %d", unauthorized.Code)
	}
	wrongRepository := "/go/" + workspace.ID + "/" + uuid.NewString() + "/example.com/private/!upper/@v/list"
	wrongScope := authBearerHTTPRequest(handler, http.MethodGet, wrongRepository, "registry.example", "Bearer "+issued.Bearer, "", "")
	if wrongScope.Code != http.StatusUnauthorized {
		t.Fatalf("cross-repository token returned %d", wrongScope.Code)
	}
	wrongHost := authBearerHTTPRequest(handler, http.MethodGet, base+"/@v/list", "assets.example", "Bearer "+issued.Bearer, "", "")
	if wrongHost.Code != http.StatusForbidden {
		t.Fatalf("wrong origin returned %d", wrongHost.Code)
	}
	head := authBearerHTTPRequest(handler, http.MethodHead, base+"/@v/v1.0.0.zip", "registry.example", "Bearer "+issued.Bearer, "", "")
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD ZIP returned status=%d bytes=%d", head.Code, head.Body.Len())
	}
	if _, err := fixture.repositoryService.SetGoNamespacePolicy(ctx, owner, workspace.ID, repo.ID, 0, "private_prefixes", []string{"example.com/private"}, true); err != nil {
		t.Fatal(err)
	}
	exerciseRealGoClient(t, ctx, fixture, modules, issued.Bearer, workspace.ID, repo.ID, modulePath, version)
	exerciseRecoveredGoClient(t, ctx, fixture, objects, workspace.ID, repo.ID, owner, issued.Bearer, modulePath, version)
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"example.com/@v/v1.0.0.info", http.StatusForbidden},
		{"example.com/private/missing/@v/v1.0.0.info", http.StatusForbidden},
		{"example.com/public/missing/@v/v1.0.0.info", http.StatusNotFound},
		{"example.net/public/@v/v1.0.0.info", http.StatusNotFound},
	} {
		response := authBearerHTTPRequest(handler, http.MethodGet, "/go/"+workspace.ID+"/"+repo.ID+"/"+tc.path, "registry.example", "Bearer "+issued.Bearer, "", "")
		if response.Code != tc.status {
			t.Fatalf("namespace proxy %s status=%d want=%d", tc.path, response.Code, tc.status)
		}
	}
	if err := fixture.repositoryService.RevokeRepositoryRole(ctx, owner, workspace.ID, repo.ID, owner, repositories.GrantReader); err != nil {
		t.Fatal(err)
	}
	revoked := authBearerHTTPRequest(handler, http.MethodGet, base+"/@v/list", "registry.example", "Bearer "+issued.Bearer, "", "")
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token returned %d", revoked.Code)
	}
}

func exerciseRealGoClient(t *testing.T, ctx context.Context, fixture authHTTPFixture, modules *gomod.Service, token, workspaceID, repositoryID, modulePath, version string) {
	t.Helper()
	var handler http.Handler
	var fallback atomic.Int64
	var checksumLookups atomic.Int64
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/fallback/") {
			fallback.Add(1)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		if strings.HasPrefix(request.URL.Path, "/sumdb/") {
			checksumLookups.Add(1)
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		handler.ServeHTTP(response, request)
	}))
	tlsServer.StartTLS()
	t.Cleanup(tlsServer.Close)
	var err error
	handler, err = NewHandler(NewHealth(fixture.db), fixture.service, fixture.workspaceService, fixture.repositoryService, fixture.artifactService, AuthHTTPConfig{CanonicalOrigin: tlsServer.URL, AssetOrigin: "https://assets.example", GoModules: modules})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	caPath := filepath.Join(root, "fixture-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(root, "goauth.sh")
	authScript := "#!/bin/sh\nprintf '%s\\n\\nAuthorization: Bearer %s\\n\\n' \"$SYNTHETIC_GO_URL\" \"$SYNTHETIC_GO_TOKEN\"\n"
	if err := os.WriteFile(authPath, []byte(authScript), 0o700); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "go.mod"), []byte("module example.com/synthetic-client\n\ngo 1.24\n\nrequire example.com/private/parent/v2 v2.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "main.go"), []byte("package main\nimport parent \"example.com/private/parent/v2\"\nfunc main() { _ = parent.Value() }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	env := []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + root,
		"GOROOT=" + runtime.GOROOT(),
		"GOTOOLCHAIN=local",
		"GOENV=off",
		"GOWORK=off",
		"GOFLAGS=-modcacherw",
		"GOCACHE=" + filepath.Join(root, "go-cache"),
		"GOMODCACHE=" + filepath.Join(root, "module-cache"),
		"GOPROXY=" + tlsServer.URL + "/go/" + workspaceID + "/" + repositoryID + "," + tlsServer.URL + "/fallback",
		"GOPRIVATE=example.com/private",
		"GONOPROXY=none",
		"GONOSUMDB=example.com/private",
		"GOSUMDB=sum.golang.org " + tlsServer.URL + "/sumdb",
		"GOAUTH=/bin/sh " + authPath,
		"SSL_CERT_FILE=" + caPath,
		"SYNTHETIC_GO_URL=" + tlsServer.URL,
		"SYNTHETIC_GO_TOKEN=" + token,
	}
	command := exec.CommandContext(ctx, goBinary, "mod", "download", "-json", modulePath+"@"+version)
	command.Dir = project
	command.Env = env
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte(fmt.Sprintf(`"Version": %q`, version))) {
		t.Fatalf("real Go client download failed: %v", err)
	}
	tidy := exec.CommandContext(ctx, goBinary, "mod", "tidy")
	tidy.Dir = project
	tidy.Env = env
	if err := tidy.Run(); err != nil {
		t.Fatalf("real Go client could not resolve private transitive modules: %v", err)
	}
	list := exec.CommandContext(ctx, goBinary, "list", "-m", "all")
	list.Dir = project
	list.Env = env
	listed, err := list.Output()
	if err != nil || !bytes.Contains(listed, []byte("example.com/private/parent/v2 v2.0.0")) || !bytes.Contains(listed, []byte("example.com/private/leaf v1.0.0")) {
		t.Fatalf("real Go client did not resolve private major and transitive dependencies: %v", err)
	}
	get := exec.CommandContext(ctx, goBinary, "get", modulePath+"@"+version)
	get.Dir = project
	get.Env = env
	if err := get.Run(); err != nil {
		t.Fatalf("real Go client could not add the private module: %v", err)
	}
	missing := exec.CommandContext(ctx, goBinary, "mod", "download", "example.com/private/missing@v1.0.0")
	missing.Dir = project
	missing.Env = env
	if err := missing.Run(); err == nil {
		t.Fatal("real Go client downloaded an absent private module")
	}
	if fallback.Load() != 0 {
		t.Fatalf("private module path reached fallback %d times", fallback.Load())
	}
	ancestor := exec.CommandContext(ctx, goBinary, "mod", "download", "example.com@v1.0.0")
	ancestor.Dir = project
	ancestor.Env = env
	if err := ancestor.Run(); err == nil || fallback.Load() != 0 {
		t.Fatalf("private namespace ancestor reached fallback: err=%v calls=%d", err, fallback.Load())
	}
	public := exec.CommandContext(ctx, goBinary, "mod", "download", "example.net/public@v1.0.0")
	public.Dir = project
	public.Env = env
	if err := public.Run(); err == nil || fallback.Load() == 0 {
		t.Fatalf("public namespace did not reach local fallback: err=%v calls=%d", err, fallback.Load())
	}
	if checksumLookups.Load() != 0 {
		t.Fatalf("private module path reached checksum database %d times", checksumLookups.Load())
	}
}

func TestGoProxyPathValidation(t *testing.T) {
	for _, path := range []string{"", "/example.com/@v/list", "example.com/../bad/@v/list", "example.com/UPPER/@v/list", "example.com/@v/../v1.0.0.zip", "example.com/@v/v1.0.0.exe", "example.com/@latest/extra"} {
		if _, _, _, ok := parseGoProxyPath(path); ok {
			t.Fatalf("unsafe path %q accepted", path)
		}
	}
}
