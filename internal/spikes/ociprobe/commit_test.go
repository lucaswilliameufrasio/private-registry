//go:build integration

package ociprobe

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Controlled pauses identify exactly where the authorization becomes stale.
// This is a characterization probe, not a production commit barrier solution.
func TestOCIRevocationBetweenAuthorizationAndEngineCommit(t *testing.T) {
	for _, scenario := range []struct {
		name          string
		recheck       bool
		pauseUpstream bool
		want          int
	}{
		{"check_only_before_dispatch", false, false, http.StatusCreated},
		{"recheck_before_dispatch", true, false, http.StatusForbidden},
		{"revoke_after_dispatch_recheck", true, true, http.StatusCreated},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			directory, err := os.MkdirTemp("/tmp/opencode", "oci-commit-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(directory); err != nil { // Owned synthetic fixture only.
					t.Error(err)
				}
			})
			backend := startStorageRegistry(t, ctx, directory, filepath.Join(directory, "storage"), false)
			if err := os.WriteFile(filepath.Join(directory, "payload.txt"), []byte("commit race fixture; never run"), 0o600); err != nil {
				t.Fatal(err)
			}
			reference := strings.TrimPrefix(backend.server.URL, "http://") + "/" + repository
			orasStorage(t, ctx, directory, "push", "--plain-http", reference+":baseline", "payload.txt:application/octet-stream")
			client := &http.Client{Timeout: 10 * time.Second}
			manifestPath := "/v2/" + repository + "/manifests/"
			get := func(address string) (int, []byte) {
				t.Helper()
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Accept", manifestMedia)
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
				_ = response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				return response.StatusCode, data
			}
			status, manifest := get(backend.server.URL + manifestPath + "baseline")
			if status != 200 {
				t.Fatal("baseline manifest absent")
			}
			paused, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			resume := func() { releaseOnce.Do(func() { close(release) }) }
			wait := func(r *http.Request) bool {
				close(paused) // Exactly one controlled commit request per scenario.
				select {
				case <-release:
					return true
				case <-r.Context().Done():
					return false
				}
			}
			engineURL, _ := url.Parse(backend.server.URL)
			engineProxy := httputil.NewSingleHostReverseProxy(engineURL)
			intermediary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if scenario.pauseUpstream && r.Method == http.MethodPut && !wait(r) {
					return
				}
				engineProxy.ServeHTTP(w, r)
			}))
			defer intermediary.Close()
			var allowed atomic.Bool
			allowed.Store(true)
			upstream, _ := url.Parse(intermediary.URL)
			proxy := httputil.NewSingleHostReverseProxy(upstream)
			gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut {
					if !allowed.Load() {
						http.Error(w, "revoked", http.StatusForbidden)
						return
					}
					if !scenario.pauseUpstream && !wait(r) {
						return
					}
					if scenario.recheck && !allowed.Load() {
						http.Error(w, "revoked at dispatch", http.StatusForbidden)
						return
					}
				}
				proxy.ServeHTTP(w, r)
			}))
			defer gateway.Close()
			defer resume() // Release controlled handlers before either server closes.
			request, err := http.NewRequestWithContext(ctx, http.MethodPut, gateway.URL+manifestPath+"racing", bytes.NewReader(manifest))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", manifestMedia)
			type result struct {
				status int
				err    error
			}
			finished := make(chan result, 1)
			go func() {
				response, err := client.Do(request)
				if err != nil {
					finished <- result{err: err}
					return
				}
				_ = response.Body.Close()
				finished <- result{status: response.StatusCode}
			}()
			select {
			case <-paused:
			case <-ctx.Done():
				t.Fatal("commit did not reach controlled pause:", ctx.Err())
			}
			if status, _ := get(backend.server.URL + manifestPath + "racing"); status != 404 {
				t.Fatal("manifest already committed before controlled revocation")
			}
			allowed.Store(false) // Revocation acknowledged before resuming the request.
			resume()
			select {
			case actual := <-finished:
				if actual.err != nil || actual.status != scenario.want {
					t.Fatalf("unexpected controlled commit result: %+v", actual)
				}
			case <-ctx.Done():
				t.Fatal("commit did not finish:", ctx.Err())
			}
			status, actual := get(backend.server.URL + manifestPath + "racing")
			if scenario.want == http.StatusCreated {
				if status != 200 || !bytes.Equal(actual, manifest) {
					t.Fatal("stale authorization did not actually commit expected manifest")
				}
			} else if status != 404 {
				t.Fatal("denied dispatch still committed manifest")
			}
			t.Logf("recheck=%v pause_upstream=%v: revocation acknowledged before engine commit; response=%d", scenario.recheck, scenario.pauseUpstream, scenario.want)
		})
	}
}
