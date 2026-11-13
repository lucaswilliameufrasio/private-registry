package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"private-registry/internal/artifacts"
	"private-registry/internal/auth"
	"private-registry/internal/bootstrap"
	"private-registry/internal/config"
	"private-registry/internal/database"
	"private-registry/internal/gomod"
	"private-registry/internal/migrations"
	"private-registry/internal/repositories"
	"private-registry/internal/secrets"
	"private-registry/internal/server"
	"private-registry/internal/storage"
	"private-registry/internal/workspaces"
)

// Exercises the CLI's actual HTTP client and packer against the real local
// router. The terminal prompts themselves are tested separately from this flow.
func TestPublishGoClientAgainstLocalRegistry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	dataDir, keyDir := filepath.Join(root, "data"), filepath.Join(root, "keys")
	for _, dir := range []string{dataDir, keyDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(keyDir, "master.key")
	if err := secrets.InitializeMasterKey(keyPath, dataDir); err != nil {
		t.Fatal(err)
	}
	key, err := secrets.LoadMasterKeyFile(keyPath, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	cfg := config.Config{DataDir: dataDir, DatabaseDriver: config.SQLite, DatabaseDSN: filepath.Join(dataDir, "registry.sqlite"), DatabaseMaxOpenConns: 4}
	db, err := database.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := migrations.Migrate(ctx, db, cfg); err != nil {
		t.Fatal(err)
	}
	const login, password = "synthetic.cli", "synthetic-cli-password-never-reuse"
	if _, err := bootstrap.CreateFirstAdmin(ctx, db, config.SQLite, bootstrap.AdminInput{LoginName: login, DisplayName: "Synthetic CLI", Email: "cli@example.invalid", Password: []byte(password), OperatorLabel: "synthetic"}); err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := db.QueryRowContext(ctx, `SELECT user_id FROM registry_instance_admins`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	authService, err := auth.New(db, config.SQLite, &key)
	if err != nil {
		t.Fatal(err)
	}
	workspaceService, err := workspaces.New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	repoService, err := repositories.New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := workspaceService.CreateWorkspace(ctx, owner, "cli-test", "CLI test")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := repoService.CreateWithFormat(ctx, owner, workspace.ID, "modules", "Modules", repositories.FormatGo)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []repositories.GrantRole{repositories.GrantPublisher, repositories.GrantReader} {
		if _, err := repoService.GrantRepositoryRole(ctx, owner, workspace.ID, repo.ID, owner, role); err != nil {
			t.Fatal(err)
		}
	}
	store, err := storage.NewFileSystem(filepath.Join(dataDir, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	artifactService, err := artifacts.New(db, config.SQLite, repoService, store, artifacts.Options{MaxUploadBytes: 1 << 20, MaxConcurrentUploads: 2})
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	modules, err := gomod.NewService(db, config.SQLite, repoService, store, gomod.Options{StagingDirectory: staging, MaxZipBytes: 1 << 20, MaxFiles: 100, MaxConcurrent: 2})
	if err != nil {
		t.Fatal(err)
	}
	var handler http.Handler
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	tlsServer.StartTLS()
	t.Cleanup(tlsServer.Close)
	handler, err = server.NewHandler(server.NewHealth(db), authService, workspaceService, repoService, artifactService, server.AuthHTTPConfig{CanonicalOrigin: tlsServer.URL, AssetOrigin: "https://assets.example", GoModules: modules})
	if err != nil {
		t.Fatal(err)
	}
	client := tlsServer.Client()
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := loginForPublish(ctx, client, tlsServer.URL, login, password)
	if err != nil || stage != "mfa_enrollment" {
		t.Fatalf("initial login stage=%q err=%v", stage, err)
	}
	data, err := publishRequest(ctx, client, tlsServer.URL, http.MethodPost, "/api/v1/auth/mfa/enrollment", "", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var enrollment struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(data, &enrollment); err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	otp := func(step int64) string {
		var message [8]byte
		binary.BigEndian.PutUint64(message[:], uint64(step))
		mac := hmac.New(sha1.New, secret)
		_, _ = mac.Write(message[:])
		digest := mac.Sum(nil)
		index := digest[len(digest)-1] & 15
		code := (uint32(digest[index])&127)<<24 | uint32(digest[index+1])<<16 | uint32(digest[index+2])<<8 | uint32(digest[index+3])
		return fmt.Sprintf("%06d", code%1000000)
	}
	step := time.Now().Unix() / 30
	if _, err := publishJSON(ctx, client, tlsServer.URL, http.MethodPost, "/api/v1/auth/mfa/enrollment/complete", map[string]string{"code": otp(step - 1)}, true); err != nil {
		t.Fatal(err)
	}
	stage, err = loginForPublish(ctx, client, tlsServer.URL, login, password)
	if err != nil || stage != "mfa_challenge" {
		t.Fatalf("MFA login stage=%q err=%v", stage, err)
	}
	if _, err := publishJSON(ctx, client, tlsServer.URL, http.MethodPost, "/api/v1/auth/mfa/challenge", map[string]string{"code": otp(step)}, true); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{"go.mod": "module example.com/private/cli\n\ngo 1.24\n", "cli.go": "package cli\n"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS == "linux" {
		script, err := exec.LookPath("script")
		if err != nil {
			t.Log("interactive CLI test unavailable: script command not installed")
		} else {
			binaryPath := filepath.Join(root, "registryctl")
			build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", binaryPath, ".")
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build CLI fixture: %v: %s", err, output)
			}
			caPath := filepath.Join(root, "fixture-ca.pem")
			if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw}), 0o600); err != nil {
				t.Fatal(err)
			}
			commandLine := fmt.Sprintf("%q publish go -url %q -workspace %q -repository %q -dir %q -version v1.1.0 -source-time %q -login %q", binaryPath, tlsServer.URL, workspace.ID, repo.ID, source, time.Now().UTC().Format(time.RFC3339Nano), login)
			command := exec.CommandContext(ctx, script, "-q", "-e", "-c", commandLine, "/dev/null")
			command.Stdin = strings.NewReader(password + "\n" + otp(step+1) + "\n")
			command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + root, "SSL_CERT_FILE=" + caPath}
			output, err := command.CombinedOutput()
			if err != nil || !bytes.Contains(output, []byte("published")) {
				t.Fatalf("interactive CLI publication failed: %v", err)
			}
			if _, err := modules.GetVersion(ctx, owner, workspace.ID, repo.ID, "example.com/private/cli", "v1.1.0"); err != nil {
				t.Fatalf("interactive CLI version not available: %v", err)
			}
		}
	}
	archive, err := os.CreateTemp(root, "packed-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = archive.Close() })
	packed, err := gomod.PackDirectory(ctx, source, "v1.0.0", archive, 100)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := uploadPackedGo(ctx, client, tlsServer.URL, workspace.ID, repo.ID, time.Now().UTC(), packed, archive, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "published") {
		t.Fatalf("publication result was not reported: %s", output.String())
	}
	fields := strings.Fields(output.String())
	if len(fields) != 3 || fields[0] != "upload_session_id:" {
		t.Fatalf("publication receipt is invalid: %s", output.String())
	}
	sessionPath := "/api/v1/workspaces/" + workspace.ID + "/repositories/" + repo.ID + "/go/uploads/" + fields[1]
	var reconciled bytes.Buffer
	if err := publicationAction(ctx, client, tlsServer.URL, sessionPath, "status", &reconciled); err != nil || !strings.Contains(reconciled.String(), `"status":"published"`) {
		t.Fatalf("published status could not be reconciled: %v", err)
	}
	reconciled.Reset()
	if err := publicationAction(ctx, client, tlsServer.URL, sessionPath, "finalize", &reconciled); err != nil || !strings.Contains(reconciled.String(), "published") {
		t.Fatalf("published receipt retry failed: %v", err)
	}
	version, err := modules.GetVersion(ctx, owner, workspace.ID, repo.ID, packed.ModulePath, packed.Version)
	if err != nil || version.ZipKey.SHA256 != packed.ZipSHA256 {
		t.Fatalf("published version not available: %v", err)
	}
	if err := logoutInteractiveSession(client, tlsServer.URL); err != nil {
		t.Fatalf("logout failed: %v", err)
	}
	if _, err := readPublicationStatus(ctx, client, tlsServer.URL, sessionPath); err == nil {
		t.Fatal("logged-out client could still read publication state")
	}
}
