package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebInterfaceIsServedOnlyOnTheCanonicalOrigin(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	get := func(path, host string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "https://"+host+path, nil)
		request.Host = host
		request.TLS = &tls.ConnectionState{}
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		return response
	}
	for path, kind := range map[string]string{"/": "text/html", "/ui/app.js": "text/javascript", "/ui/app.css": "text/css"} {
		response := get(path, "registry.example")
		csp := response.Header().Get("Content-Security-Policy")
		if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), kind) || !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") || response.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: %d %v", path, response.Code, response.Header())
		}
	}
	index := get("/", "registry.example").Body.String()
	if strings.Contains(index, "<script>") || !strings.Contains(index, `src="/ui/app.js"`) {
		t.Fatal("index has inline script or does not load the application")
	}
	for _, path := range []string{"/ui/../go.mod", "/ui/static/app.js", "/ui/index.html", "/ui/missing.js"} {
		if response := get(path, "registry.example"); response.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, response.Code)
		}
	}
	// The asset origin never serves the interface.
	if response := get("/", "assets.example"); response.Code != http.StatusNotFound {
		t.Fatalf("interface on the asset origin: %d", response.Code)
	}
	// Plain HTTP from an untrusted peer is refused.
	request := httptest.NewRequest(http.MethodGet, "http://registry.example/", nil)
	request.Host = "registry.example"
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("interface over plain HTTP: %d", response.Code)
	}
	methods := authHTTPRequest(fixture.handler, http.MethodGet, "/api/v1/auth/methods", "", "", "registry.example")
	if methods.Code != http.StatusOK || !strings.Contains(methods.Body.String(), `"passkeys":true`) {
		t.Fatalf("auth methods: %d %s", methods.Code, methods.Body.String())
	}
}
