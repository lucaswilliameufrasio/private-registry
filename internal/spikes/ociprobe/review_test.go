//go:build integration

package ociprobe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This probe is NOT a review workflow implementation. It characterizes a real
// client's response and the native engine's blob visibility under a commit gate.
func TestOCIReviewBlocksNativeSuccessAndPendingBlobDownloads(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	directory, err := os.MkdirTemp("/tmp/opencode", "oci-review-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil { // Owned synthetic fixture only.
			t.Error(err)
		}
	})
	backend := startStorageRegistry(t, ctx, directory, filepath.Join(directory, "storage"), false)
	upstream, _ := url.Parse(backend.server.URL)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	// The backend's upload locations must be rewritten through this probe gate,
	// otherwise the test itself would introduce a data-plane bypass.
	var publicURL string
	var published sync.Map // Repository-qualified blob paths, never global hashes.
	var reviewApproved atomic.Bool
	var publisherAllowed atomic.Bool
	var enforceVisibility atomic.Bool
	publisherAllowed.Store(true)
	var blobLeakObserved atomic.Bool
	pendingPath := "/v2/" + repository + "/manifests/reviewed"
	type manifestBodyKey struct{}
	proxy.ModifyResponse = func(response *http.Response) error {
		if location := response.Header.Get("Location"); strings.HasPrefix(location, backend.server.URL+"/") {
			response.Header.Set("Location", publicURL+strings.TrimPrefix(location, backend.server.URL))
		}
		if response.Request.Method != http.MethodPut || !strings.Contains(response.Request.URL.Path, "/manifests/") || response.StatusCode != http.StatusCreated {
			return nil
		}
		data, ok := response.Request.Context().Value(manifestBodyKey{}).([]byte)
		if !ok {
			return errors.New("fixture lost manifest input")
		}
		var manifest struct {
			Config ociDescriptor   `json:"config"`
			Layers []ociDescriptor `json:"layers"`
		}
		if err := json.Unmarshal(data, &manifest); err != nil {
			return err
		}
		prefix, _, _ := strings.Cut(response.Request.URL.Path, "/manifests/")
		for _, descriptor := range append([]ociDescriptor{manifest.Config}, manifest.Layers...) {
			published.Store(prefix+"/blobs/"+descriptor.Digest, true)
		}
		return nil
	}
	gate := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.Contains(r.URL.Path, "/blobs/") && !strings.Contains(r.URL.Path, "/uploads/") {
			_, visible := published.Load(r.URL.Path)
			if enforceVisibility.Load() && !visible {
				http.NotFound(w, r)
				return
			}
			if !visible {
				blobLeakObserved.Store(true)
			}
		}
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/") {
			if !publisherAllowed.Load() || (r.URL.Path == pendingPath && !reviewApproved.Load()) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"errors":[{"code":"DENIED","message":"native publication blocked; approval and current permissions required"}]}`)
				return
			}
			data, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
			if err != nil || len(data) > 1<<20 {
				http.Error(w, "fixture manifest too large", http.StatusRequestEntityTooLarge)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), manifestBodyKey{}, data))
			r.Body = io.NopCloser(bytes.NewReader(data))
		}
		proxy.ServeHTTP(w, r)
	}))
	publicURL = "http://" + gate.Listener.Addr().String()
	gate.Start()
	defer gate.Close()
	reference := strings.TrimPrefix(publicURL, "http://") + "/" + repository
	runPush := func(tag, filename string) (string, error) {
		command := exec.CommandContext(ctx, filepath.Join(toolsRoot, "oras"), "push", "--plain-http", "--registry-config", filepath.Join(directory, "auth.json"), reference+":"+tag, filename+":application/octet-stream")
		command.Dir = directory
		command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + directory, "GOMAXPROCS=2"}
		command.WaitDelay = 2 * time.Second
		output, err := command.CombinedOutput()
		return string(output), err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	read := func(method, path string) (int, []byte) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, publicURL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Accept", manifestMedia)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err := errors.Join(readErr, response.Body.Close()); err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	payload := []byte("already published artifact remains available")
	if err := os.WriteFile(filepath.Join(directory, "published.txt"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := runPush("published", "published.txt"); err != nil {
		t.Fatalf("baseline publication failed: %v %s", err, output)
	}
	pending := []byte("pending private artifact must not be downloadable")
	if err := os.WriteFile(filepath.Join(directory, "pending.txt"), pending, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := runPush("reviewed", "pending.txt"); err == nil || !strings.Contains(strings.ToLower(output), "denied: native publication blocked") {
		t.Fatalf("ORAS reported native publication success before approval: %v %s", err, output)
	}
	if status, _ := read(http.MethodGet, pendingPath); status != 404 {
		t.Fatalf("pending manifest became visible: %d", status)
	}
	hash := sha256.Sum256(pending)
	pendingBlob := "/v2/" + repository + "/blobs/sha256:" + hex.EncodeToString(hash[:])
	if status, data := read(http.MethodGet, pendingBlob); status != 200 || !bytes.Equal(data, pending) || !blobLeakObserved.Load() {
		t.Fatal("manifest-only gate visibility characterization changed")
	}
	// Mitigation proof: downloads require published reachability. In production
	// this projection must be durable, reconciled and authorized per repository.
	enforceVisibility.Store(true)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		if status, _ := read(method, pendingBlob); status != 404 {
			t.Fatalf("pending blob leaked under reachability gate: %s %d", method, status)
		}
	}
	previous := sha256.Sum256(payload)
	previousBlob := "/v2/" + repository + "/blobs/sha256:" + hex.EncodeToString(previous[:])
	if status, data := read(http.MethodGet, previousBlob); status != 200 || !bytes.Equal(data, payload) {
		t.Fatal("reachability gate blocked existing publication")
	}
	// Approval is an external synthetic input, not a fake durable review API.
	// Current permission still has to be checked before manifest release.
	reviewApproved.Store(true)
	publisherAllowed.Store(false)
	if output, err := runPush("reviewed", "pending.txt"); err == nil || !strings.Contains(strings.ToLower(output), "denied: native publication blocked") {
		t.Fatalf("approval bypassed current publisher permission: %v %s", err, output)
	}
	if status, _ := read(http.MethodGet, pendingPath); status != 404 {
		t.Fatal("unauthorized approved attempt became visible")
	}
	publisherAllowed.Store(true)
	if output, err := runPush("reviewed", "pending.txt"); err != nil {
		t.Fatalf("authorized approved retry failed: %v %s", err, output)
	}
	if status, _ := read(http.MethodGet, pendingPath); status != 200 {
		t.Fatal("approved committed manifest absent")
	}
	if status, data := read(http.MethodGet, pendingBlob); status != 200 || !bytes.Equal(data, pending) {
		t.Fatal("approved committed blob not downloadable")
	}
	t.Log("ORAS push fails without manifest approval; native pending blob initially readable; published-reachability gate hides GET/HEAD, preserves old content, and permits retry only with approval plus current permission")
}
