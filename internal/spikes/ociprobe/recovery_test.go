//go:build integration

package ociprobe

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"private-registry/internal/spikes/sqlitebackup"
)

type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    map[string]string `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

const indexMedia = "application/vnd.oci.image.index.v1+json"
const manifestMedia = "application/vnd.oci.image.manifest.v1+json"

func blob(t *testing.T, layout, media string, data []byte) ociDescriptor {
	t.Helper()
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	path := filepath.Join(layout, "blobs", "sha256")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, digest), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return ociDescriptor{MediaType: media, Digest: "sha256:" + digest, Size: int64(len(data))}
}

func imageLayout(t *testing.T, directory string) ociDescriptor {
	t.Helper()
	var uncompressed bytes.Buffer
	archive := tar.NewWriter(&uncompressed)
	payload := []byte("synthetic OCI layer; never run")
	if err := archive.WriteHeader(&tar.Header{Name: "fixture.txt", Mode: 0o600, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	if _, err := zip.Write(uncompressed.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zip.Close(); err != nil {
		t.Fatal(err)
	}
	layer := blob(t, directory, "application/vnd.oci.image.layer.v1.tar+gzip", compressed.Bytes())
	diff := sha256.Sum256(uncompressed.Bytes())
	var children []ociDescriptor
	for _, architecture := range []string{"amd64", "arm64"} {
		config, err := json.Marshal(map[string]any{"architecture": architecture, "os": "linux", "config": map[string]any{},
			"rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + hex.EncodeToString(diff[:])}}})
		if err != nil {
			t.Fatal(err)
		}
		configuration := blob(t, directory, "application/vnd.oci.image.config.v1+json", config)
		manifest, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": manifestMedia, "config": configuration, "layers": []ociDescriptor{layer}})
		if err != nil {
			t.Fatal(err)
		}
		child := blob(t, directory, manifestMedia, manifest)
		child.Platform = map[string]string{"os": "linux", "architecture": architecture}
		children = append(children, child)
	}
	index, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": indexMedia, "manifests": children})
	if err != nil {
		t.Fatal(err)
	}
	root := blob(t, directory, indexMedia, index)
	root.Annotations = map[string]string{"org.opencontainers.image.ref.name": "multi"}
	catalog, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []ociDescriptor{root}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "index.json"), catalog, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// This verifier traverses every referenced descriptor, independent of ORAS's
// success message. It is restricted to this synthetic profile and bounded data.
func verifyGraph(directory string, root ociDescriptor) (int, error) {
	visited := map[string]bool{}
	var visit func(ociDescriptor) error
	visit = func(descriptor ociDescriptor) error {
		prefix, digest, ok := strings.Cut(descriptor.Digest, ":")
		decoded, err := hex.DecodeString(digest)
		if !ok || prefix != "sha256" || err != nil || len(decoded) != sha256.Size || descriptor.Size < 0 || descriptor.Size > 8<<20 {
			return errors.New("invalid fixture descriptor")
		}
		if visited[descriptor.Digest] {
			return nil
		}
		if len(visited) >= 32 {
			return errors.New("fixture graph exceeds node budget")
		}
		file, err := os.Open(filepath.Join(directory, "blobs", "sha256", digest))
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, descriptor.Size+1))
		if err := errors.Join(readErr, file.Close()); err != nil {
			return err
		}
		hash := sha256.Sum256(data)
		if int64(len(data)) != descriptor.Size || hex.EncodeToString(hash[:]) != digest {
			return errors.New("OCI content digest/size mismatch")
		}
		visited[descriptor.Digest] = true
		if descriptor.MediaType == indexMedia || descriptor.MediaType == manifestMedia {
			var document struct {
				SchemaVersion int             `json:"schemaVersion"`
				MediaType     string          `json:"mediaType"`
				Manifests     []ociDescriptor `json:"manifests"`
				Config        ociDescriptor   `json:"config"`
				Layers        []ociDescriptor `json:"layers"`
			}
			if err := json.Unmarshal(data, &document); err != nil {
				return err
			}
			if document.SchemaVersion != 2 || document.MediaType != descriptor.MediaType {
				return errors.New("invalid fixture manifest/index")
			}
			children := document.Manifests
			if descriptor.MediaType == manifestMedia {
				children = append([]ociDescriptor{document.Config}, document.Layers...)
			}
			for _, child := range children {
				if err := visit(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	err := visit(root)
	return len(visited), err
}

type registryFixture struct {
	server *httptest.Server
	cmd    *exec.Cmd
	config string
	socket string
}

func startStorageRegistry(t *testing.T, ctx context.Context, directory, storage string, readonly bool) *registryFixture {
	t.Helper()
	socket := filepath.Join(directory, "registry.sock")
	upstream, _ := url.Parse("http://registry.internal")
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	proxy.Transport = transport
	server := httptest.NewServer(proxy)
	config := filepath.Join(directory, "config.yml")
	text := fmt.Sprintf(`version: 0.1
log:
  level: error
storage:
  filesystem:
    rootdirectory: %s
  maintenance:
    readonly:
      enabled: %t
  redirect:
    disable: true
http:
  net: unix
  addr: %s
  host: %s
  secret: synthetic-storage-fixture
`, storage, readonly, socket, server.URL)
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, filepath.Join(toolsRoot, "registry"), "serve", config)
	command.WaitDelay = 2 * time.Second
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "GOMAXPROCS=2", "GOMEMLIMIT=256MiB", "OTEL_SDK_DISABLED=true"}
	if err := command.Start(); err != nil {
		server.Close()
		t.Fatal(err)
	}
	fixture := &registryFixture{server: server, cmd: command, config: config, socket: socket}
	t.Cleanup(func() {
		fixture.stop()
		transport.CloseIdleConnections()
	})
	for {
		if _, err := os.Stat(socket); err == nil {
			if err := os.Chmod(socket, 0o600); err != nil {
				t.Fatal(err)
			}
			break
		}
		if err := ctx.Err(); err != nil {
			t.Fatal("storage registry did not become ready:", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fixture
}

func (f *registryFixture) stop() {
	if f.cmd == nil {
		return
	}
	f.server.Close()
	_ = f.cmd.Process.Signal(os.Interrupt)
	_ = f.cmd.Process.Kill()
	_ = f.cmd.Wait()
	_ = os.Remove(f.socket) // Owned Unix socket; SIGKILL may leave it behind.
	f.cmd = nil
}

func orasStorage(t *testing.T, ctx context.Context, directory string, args ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, filepath.Join(toolsRoot, "oras"), args...)
	command.WaitDelay = 2 * time.Second
	command.Dir = directory
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + directory, "GOMAXPROCS=2"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("ORAS storage probe: %v %s", err, output)
	}
	return strings.TrimSpace(string(output))
}

func tarLayout(directory, destination string) (err error) {
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	archive := tar.NewWriter(output)
	defer func() { err = errors.Join(err, archive.Close(), output.Close()) }()
	return filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 8<<20 {
			return errors.New("fixture archive requires bounded regular files")
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		if err := archive.WriteHeader(&tar.Header{Name: filepath.ToSlash(name), Mode: 0o600, Size: info.Size()}); err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(archive, file)
		return errors.Join(copyErr, file.Close())
	})
}

func TestOCIIndexExportRestoreAndReadOnlyGC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	directory, err := os.MkdirTemp("/tmp/opencode", "oci-recovery-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil { // Owned synthetic fixture only.
			t.Error(err)
		}
	})
	seed := filepath.Join(directory, "seed")
	root := imageLayout(t, seed)
	storage := filepath.Join(directory, "source-storage")
	source := startStorageRegistry(t, ctx, directory, storage, false)
	reference := strings.TrimPrefix(source.server.URL, "http://") + "/" + repository
	orasStorage(t, ctx, directory, "cp", "--from-oci-layout", "--to-plain-http", "seed:multi", reference+":multi")
	if digest := orasStorage(t, ctx, directory, "resolve", "--plain-http", reference+":multi"); digest != root.Digest {
		t.Fatalf("seed index digest changed: %s", digest)
	}
	// Commit a blob with no manifest reference, so GC must actually delete data.
	orphan := []byte("synthetic unreferenced blob")
	orphanHash := sha256.Sum256(orphan)
	orphanDigest := "sha256:" + hex.EncodeToString(orphanHash[:])
	client := &http.Client{Timeout: 5 * time.Second}
	request, err := http.NewRequestWithContext(ctx, "POST", source.server.URL+"/v2/"+repository+"/blobs/uploads/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 202 {
		t.Fatal("orphan upload did not start")
	}
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(location.String(), source.server.URL+"/") {
		t.Fatal("orphan upload escaped owned fixture")
	}
	query := location.Query()
	query.Set("digest", orphanDigest)
	location.RawQuery = query.Encode()
	request, err = http.NewRequestWithContext(ctx, "PUT", location.String(), bytes.NewReader(orphan))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 201 {
		t.Fatalf("orphan upload did not complete: %d", response.StatusCode)
	}
	source.stop()
	// All mutable traffic is denied by the motor while export/GC run. This
	// maintenance-mode proof is not a durable production lease/pin protocol.
	readonly := startStorageRegistry(t, ctx, directory, storage, true)
	reference = strings.TrimPrefix(readonly.server.URL, "http://") + "/" + repository
	request, _ = http.NewRequestWithContext(ctx, "HEAD", readonly.server.URL+"/v2/"+repository+"/blobs/"+orphanDigest, nil)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("unreferenced blob was not readable before GC")
	}
	request, _ = http.NewRequestWithContext(ctx, "POST", readonly.server.URL+"/v2/"+repository+"/blobs/uploads/", nil)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("read-only source did not explicitly reject upload: %d", response.StatusCode)
	}
	// Index copy traverses both architectures and their shared layer.
	orasStorage(t, ctx, directory, "cp", "--from-plain-http", "--to-oci-layout", reference+":multi", "export:multi")
	exported := filepath.Join(directory, "export")
	if count, err := verifyGraph(exported, root); err != nil || count != 6 {
		t.Fatalf("export omitted or corrupted reachable graph: %d %v", count, err)
	}
	plain := filepath.Join(directory, "export.tar")
	sealed := filepath.Join(directory, "backup.age")
	if err := tarLayout(exported, plain); err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlitebackup.Encrypt(ctx, plain, sealed, identity.Recipient()); err != nil {
		t.Fatal(err)
	}
	gc := exec.CommandContext(ctx, filepath.Join(toolsRoot, "registry"), "garbage-collect", "--quiet", readonly.config)
	gc.Env = []string{"PATH=" + os.Getenv("PATH"), "GOMAXPROCS=2", "GOMEMLIMIT=256MiB", "OTEL_SDK_DISABLED=true"}
	if output, err := gc.CombinedOutput(); err != nil {
		t.Fatalf("real Distribution GC failed: %v %s", err, output)
	}
	if digest := orasStorage(t, ctx, directory, "resolve", "--plain-http", reference+":multi"); digest != root.Digest {
		t.Fatal("GC lost the tagged image index")
	}
	orasStorage(t, ctx, directory, "cp", "--from-plain-http", "--to-oci-layout", reference+":multi", "after-gc:multi")
	if count, err := verifyGraph(filepath.Join(directory, "after-gc"), root); err != nil || count != 6 {
		t.Fatalf("GC lost reachable child manifest/config/layer: %d %v", count, err)
	}
	request, _ = http.NewRequestWithContext(ctx, "HEAD", readonly.server.URL+"/v2/"+repository+"/blobs/"+orphanDigest, nil)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatalf("unreferenced blob remained after GC: %d", response.StatusCode)
	}
	readonly.stop()
	// Eliminate every source copy, not just the dashboard/inventory.
	for _, path := range []string{storage, seed, exported, filepath.Join(directory, "after-gc"), plain} {
		if err := os.RemoveAll(path); err != nil { // Exact paths created by this test.
			t.Fatal(err)
		}
	}
	recoveredTar := filepath.Join(directory, "recovered.tar")
	if err := sqlitebackup.Decrypt(ctx, sealed, recoveredTar, identity); err != nil {
		t.Fatal(err)
	}
	restored := startStorageRegistry(t, ctx, directory, filepath.Join(directory, "restored-storage"), false)
	restoredReference := strings.TrimPrefix(restored.server.URL, "http://") + "/" + repository
	orasStorage(t, ctx, directory, "cp", "--from-oci-layout", "--to-plain-http", "recovered.tar:multi", restoredReference+":multi")
	if digest := orasStorage(t, ctx, directory, "resolve", "--plain-http", restoredReference+":multi"); digest != root.Digest {
		t.Fatal("restored index digest changed")
	}
	orasStorage(t, ctx, directory, "cp", "--from-plain-http", "--to-oci-layout", restoredReference+":multi", "verified:multi")
	if count, err := verifyGraph(filepath.Join(directory, "verified"), root); err != nil || count != 6 {
		t.Fatalf("restored graph differs: %d %v", count, err)
	}
	index, err := os.ReadFile(filepath.Join(directory, "verified", "blobs", "sha256", strings.TrimPrefix(root.Digest, "sha256:")))
	if err != nil {
		t.Fatal(err)
	}
	var platforms struct {
		Manifests []ociDescriptor `json:"manifests"`
	}
	if err := json.Unmarshal(index, &platforms); err != nil || len(platforms.Manifests) != 2 {
		t.Fatal("restored index lost platform descriptors")
	}
	for _, manifest := range platforms.Manifests {
		architecture := manifest.Platform["architecture"]
		if manifest.Platform["os"] != "linux" || (architecture != "amd64" && architecture != "arm64") {
			t.Fatal("unexpected restored platform")
		}
		layout := "platform-" + architecture
		orasStorage(t, ctx, directory, "cp", "--platform", "linux/"+architecture, "--from-plain-http", "--to-oci-layout", restoredReference+":multi", layout+":selected")
		if count, err := verifyGraph(filepath.Join(directory, layout), manifest); err != nil || count != 3 {
			t.Fatalf("ORAS platform selection changed graph %s: %d %v", architecture, count, err)
		}
	}
	t.Log("OCI amd64/arm64 index: six digest-verified reachable blobs restored from age after source removal; read-only GC removed orphan and preserved both platforms/shared layer")
}

func TestOCIExportVerifierRejectsMissingAndCorruptBlobs(t *testing.T) {
	for _, kind := range []string{"corrupted_root", "missing_child"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			root := imageLayout(t, directory)
			if count, err := verifyGraph(directory, root); err != nil || count != 6 {
				t.Fatal("control graph invalid:", count, err)
			}
			rootPath := filepath.Join(directory, "blobs", "sha256", strings.TrimPrefix(root.Digest, "sha256:"))
			if kind == "corrupted_root" {
				if err := os.WriteFile(rootPath, []byte("corrupted"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				data, err := os.ReadFile(rootPath)
				if err != nil {
					t.Fatal(err)
				}
				var index struct {
					Manifests []ociDescriptor `json:"manifests"`
				}
				if err := json.Unmarshal(data, &index); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(directory, "blobs", "sha256", strings.TrimPrefix(index.Manifests[0].Digest, "sha256:"))); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := verifyGraph(directory, root); err == nil {
				t.Fatal("incomplete/corrupt export accepted by graph verifier")
			}
		})
	}
}
