//go:build integration

package ociprobe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Isolated storage probe: policy inputs are synthetic, not JWT/RBAC. Native
// token verification is covered separately; no production gateway is implied.
func TestOCIMountRequiresBothPermissionsAndPublishedSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	directory, err := os.MkdirTemp("/tmp/opencode", "oci-mount-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil { // Own synthetic paths only.
			t.Error(err)
		}
	})
	backend := startStorageRegistry(t, ctx, directory, filepath.Join(directory, "storage"), false)
	source := "fixture/source/image"
	destination := "fixture/destination/image"
	approved := []byte("published source layer")
	pending := []byte("pending source layer must not be mounted")
	digest := func(payload []byte) string {
		hash := sha256.Sum256(payload)
		return "sha256:" + hex.EncodeToString(hash[:])
	}
	approvedDigest, pendingDigest := digest(approved), digest(pending)
	if err := os.WriteFile(filepath.Join(directory, "approved.txt"), approved, 0o600); err != nil {
		t.Fatal(err)
	}
	reference := strings.TrimPrefix(backend.server.URL, "http://") + "/" + source
	orasStorage(t, ctx, directory, "push", "--plain-http", reference+":published", "approved.txt:application/octet-stream")
	client := &http.Client{Timeout: 5 * time.Second}
	call := func(method, address string, payload []byte) (int, http.Header, []byte) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		if payload != nil {
			request.Header.Set("Content-Type", "application/octet-stream")
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, response.Header, data
	}
	status, headers, _ := call(http.MethodPost, backend.server.URL+"/v2/"+source+"/blobs/uploads/", nil)
	if status != 202 {
		t.Fatal("pending upload did not start")
	}
	location, err := url.Parse(headers.Get("Location"))
	if err != nil || !strings.HasPrefix(location.String(), backend.server.URL+"/") {
		t.Fatal("upload escaped owned engine")
	}
	query := location.Query()
	query.Set("digest", pendingDigest)
	location.RawQuery = query.Encode()
	if status, _, _ := call(http.MethodPut, location.String(), pending); status != 201 {
		t.Fatal("pending blob commit failed")
	}
	mountURL := func(base, from, hash string) string {
		return base + "/v2/" + destination + "/blobs/uploads/?" + url.Values{"from": {from}, "mount": {hash}}.Encode()
	}
	// Native storage links any committed source blob, not only blobs belonging
	// to a reviewed/public manifest. Mount alone must never grant distribution.
	status, headers, _ = call(http.MethodPost, mountURL(backend.server.URL, source, pendingDigest), nil)
	if status != 201 || headers.Get("Docker-Content-Digest") != pendingDigest {
		t.Fatalf("native pending mount characterization changed: %d", status)
	}
	if status, _, data := call(http.MethodGet, backend.server.URL+"/v2/"+destination+"/blobs/"+pendingDigest, nil); status != 200 || !bytes.Equal(data, pending) {
		t.Fatal("native pending mount did not expose bytes at destination")
	}
	missingDigest := digest([]byte("never uploaded"))
	if status, _, _ := call(http.MethodPost, mountURL(backend.server.URL, source, missingDigest), nil); status != 202 {
		t.Fatalf("missing native mount did not fall back to upload: %d", status)
	}
	if status, _, _ := call(http.MethodGet, backend.server.URL+"/v2/"+destination+"/blobs/"+missingDigest, nil); status != 404 {
		t.Fatal("fallback upload was mistaken for mounted content")
	}
	var enforce, sourcePull, destinationPush atomic.Bool
	sourcePull.Store(true)
	destinationPush.Store(true)
	upstream, _ := url.Parse(backend.server.URL)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	var gateURL string
	proxy.ModifyResponse = func(response *http.Response) error {
		if location := response.Header.Get("Location"); strings.HasPrefix(location, backend.server.URL+"/") {
			response.Header.Set("Location", gateURL+strings.TrimPrefix(location, backend.server.URL))
		}
		return nil
	}
	gate := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enforce.Load() {
			if r.Method == http.MethodPost && r.URL.Path == "/v2/"+destination+"/blobs/uploads/" {
				values := r.URL.Query()
				if len(values["mount"]) != 1 || len(values["from"]) != 1 {
					http.Error(w, "ambiguous fixture mount", http.StatusBadRequest)
					return
				}
				if values.Get("from") != source || !sourcePull.Load() || !destinationPush.Load() {
					http.Error(w, "both current permissions required", http.StatusForbidden)
					return
				}
				// One known published source descriptor. A real projection must be
				// durable/reconciled, not a digest allowlist in the gateway.
				if values.Get("mount") != approvedDigest {
					http.NotFound(w, r)
					return
				}
			}
			if (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.Contains(r.URL.Path, "/blobs/") {
				if r.URL.Path != "/v2/"+source+"/blobs/"+approvedDigest || !sourcePull.Load() {
					// Destination has no published manifest even after mount. A
					// globally approved digest must not become repository access.
					http.NotFound(w, r)
					return
				}
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	gateURL = "http://" + gate.Listener.Addr().String()
	gate.Start()
	defer gate.Close()
	enforce.Store(true)
	for _, permissions := range [][2]bool{{false, true}, {true, false}, {false, false}} {
		sourcePull.Store(permissions[0])
		destinationPush.Store(permissions[1])
		if status, _, _ := call(http.MethodPost, mountURL(gateURL, source, approvedDigest), nil); status != 403 {
			t.Fatalf("mount accepted without both permissions %v: %d", permissions, status)
		}
	}
	sourcePull.Store(true)
	destinationPush.Store(true)
	for _, from := range []string{"other/workspace/image", source} {
		hash := approvedDigest
		want := 403
		if from == source {
			hash, want = pendingDigest, 404
		}
		if status, _, _ := call(http.MethodPost, mountURL(gateURL, from, hash), nil); status != want {
			t.Fatalf("unauthorized/pending mount accepted: %d", status)
		}
	}
	if status, _, _ := call(http.MethodPost, mountURL(gateURL, source, approvedDigest)+"&from=other%2Fimage", nil); status != 400 {
		t.Fatal("ambiguous source accepted")
	}
	status, headers, _ = call(http.MethodPost, mountURL(gateURL, source, approvedDigest), nil)
	if status != 201 || headers.Get("Docker-Content-Digest") != approvedDigest || !strings.HasPrefix(headers.Get("Location"), gateURL+"/") {
		t.Fatalf("authorized published mount failed or bypassed gateway: %d %v", status, headers)
	}
	// Engine storage link exists but public reachability does not yet exist.
	if status, _, data := call(http.MethodGet, backend.server.URL+"/v2/"+destination+"/blobs/"+approvedDigest, nil); status != 200 || !bytes.Equal(data, approved) {
		t.Fatal("authorized mount did not actually link content")
	}
	for _, hash := range []string{approvedDigest, pendingDigest} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			if status, _, _ := call(method, gateURL+"/v2/"+destination+"/blobs/"+hash, nil); status != 404 {
				t.Fatal("mounted content became distribution without destination publication")
			}
		}
	}
	if status, _, data := call(http.MethodGet, gateURL+"/v2/"+source+"/blobs/"+approvedDigest, nil); status != 200 || !bytes.Equal(data, approved) {
		t.Fatal("source published download was interrupted")
	}
	sourcePull.Store(false)
	if status, _, _ := call(http.MethodPost, mountURL(gateURL, source, approvedDigest), nil); status != 403 {
		t.Fatal("prior mount bypassed current source permission")
	}
	t.Log("native mount exposes pending source blob in destination; experimental gate requires both current permissions and published source, and mount never grants destination distribution")
}
