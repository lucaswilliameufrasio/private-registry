//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServePubProtocolRequiresOptIn(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			root := t.TempDir()
			keys := filepath.Join(root, "keys")
			if err := os.Mkdir(keys, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("REGISTRY_DATA_DIR", filepath.Join(root, "data"))
			t.Setenv("REGISTRY_DATABASE_DRIVER", "sqlite")
			t.Setenv("REGISTRY_MASTER_KEY_FILE", filepath.Join(keys, "master.key"))
			t.Setenv("REGISTRY_CANONICAL_ORIGIN", "https://registry.example")
			t.Setenv("REGISTRY_ASSET_ORIGIN", "https://assets.example")
			t.Setenv("REGISTRY_TRUSTED_PROXIES", "127.0.0.1")
			t.Setenv("REGISTRY_EXPERIMENTAL_PUB", map[bool]string{false: "false", true: "true"}[enabled])
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			t.Setenv("REGISTRY_LISTEN_ADDRESS", address)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			if err := run(ctx, []string{"migrate"}, logger); err != nil {
				t.Fatal(err)
			}
			if err := run(ctx, []string{"init-master-key"}, logger); err != nil {
				t.Fatal(err)
			}
			serverCtx, stop := context.WithCancel(ctx)
			result := make(chan error, 1)
			go func() { result <- run(serverCtx, []string{"serve"}, logger) }()
			defer func() {
				stop()
				if err := <-result; err != nil && !errors.Is(err, context.Canceled) {
					t.Errorf("stop server: %v", err)
				}
			}()
			client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
			defer client.CloseIdleConnections()
			for {
				response, err := client.Get("http://" + address + "/readyz")
				if err == nil {
					ready := response.StatusCode == http.StatusNoContent
					_ = response.Body.Close()
					if ready {
						break
					}
				}
				select {
				case <-ctx.Done():
					t.Fatal("server did not become ready")
				case <-time.After(20 * time.Millisecond):
				}
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/pub/00000000-0000-0000-0000-000000000001/00000000-0000-0000-0000-000000000002/api/packages/fixture", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Host = "registry.example"
			request.Header.Set("X-Forwarded-Proto", "https")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			want := http.StatusNotFound
			if enabled {
				want = http.StatusUnauthorized
			}
			if response.StatusCode != want {
				t.Fatalf("Pub route status=%d want=%d", response.StatusCode, want)
			}
		})
	}
}
