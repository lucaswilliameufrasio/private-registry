package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"private-registry/internal/config"
	"private-registry/internal/database"
)

func TestHealthProbesReportLivenessAndDatabaseReadiness(t *testing.T) {
	db, err := database.Open(context.Background(), config.Config{
		DataDir:              filepath.Join(t.TempDir(), "data"),
		DatabaseDriver:       config.SQLite,
		DatabaseDSN:          filepath.Join(t.TempDir(), "data", "registry.sqlite"),
		DatabaseMaxOpenConns: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

	health := NewHealth(db)
	handler := health.Handler()

	if got := requestStatus(handler, "/livez"); got != http.StatusNoContent {
		t.Fatalf("unexpected liveness status: %d", got)
	}
	if got := requestStatus(handler, "/readyz"); got != http.StatusNoContent {
		t.Fatalf("unexpected readiness status with a live database: %d", got)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if got := requestStatus(handler, "/livez"); got != http.StatusNoContent {
		t.Fatalf("liveness depended on the database: %d", got)
	}
	if got := requestStatus(handler, "/readyz"); got != http.StatusServiceUnavailable {
		t.Fatalf("readiness did not fail closed for a closed database: %d", got)
	}
}

func TestHealthIsUnreadyWhileDraining(t *testing.T) {
	health := NewHealth(nil)
	health.MarkDraining()
	handler := health.Handler()

	if got := requestStatus(handler, "/readyz"); got != http.StatusServiceUnavailable {
		t.Fatalf("draining server remained ready: %d", got)
	}
	if got := requestStatus(handler, "/livez"); got != http.StatusNoContent {
		t.Fatalf("draining server was not live: %d", got)
	}
}

func requestStatus(handler http.Handler, path string) int {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Code
}

func TestServeDrainsInflightRequestsBeforeReturning(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	draining := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- Serve(ctx, listener, handler, func() { close(draining) }, 3*time.Second)
	}()

	responseResult := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + listener.Addr().String())
		if err == nil {
			defer response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				responseResult <- fmt.Errorf("unexpected in-flight response status: %d", response.StatusCode)
				return
			}
		}
		responseResult <- err
	}()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request did not start")
	}
	cancel()
	select {
	case <-draining:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not enter draining state")
	}
	select {
	case err := <-serveResult:
		t.Fatalf("server returned before in-flight request was released: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-responseResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request did not finish")
	}
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not exit after draining")
	}
}
