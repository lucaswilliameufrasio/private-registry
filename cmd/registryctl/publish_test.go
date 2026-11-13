package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"private-registry/internal/gomod"
)

func TestUploadPackedGoReviewAndRetry(t *testing.T) {
	const session = "00000000-0000-4000-8000-000000000001"
	for _, test := range []struct {
		name        string
		initial     string
		review      string
		wantUpload  int
		wantPublish int
		wantText    string
	}{
		{"pending review", "receiving", "awaiting_review", 1, 0, "awaiting human review"},
		{"retry uploaded", "uploaded", "approved", 0, 1, "published"},
		{"no review", "receiving", "not_required", 1, 1, "published"},
	} {
		t.Run(test.name, func(t *testing.T) {
			status := test.initial
			var uploads, publishes int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Origin") == "" || (r.Method != http.MethodGet && r.Header.Get("X-CSRF-Token") != "synthetic-csrf") {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				switch {
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/uploads"):
					_, _ = fmt.Fprintf(w, `{"upload_session_id":%q}`, session)
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/"+session):
					_, _ = fmt.Fprintf(w, `{"status":%q,"review_state":%q,"recovery_invalidated":false}`, status, test.review)
				case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/content"):
					uploads++
					body, _ := io.ReadAll(r.Body)
					if string(body) != "synthetic zip" {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					status = "uploaded"
					w.WriteHeader(http.StatusNoContent)
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/publish"):
					publishes++
					w.WriteHeader(http.StatusNoContent)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			client := server.Client()
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			client.Jar = jar
			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(req.URL, []*http.Cookie{{Name: "__Host-registry-csrf", Value: "synthetic-csrf", Path: "/", Secure: true}})
			var output bytes.Buffer
			packed := gomod.PackedModule{ModulePath: "example.com/private/module", Version: "v1.0.0", ModBytes: []byte("module example.com/private/module\n"), ZipSize: 13, ZipSHA256: strings.Repeat("a", 64)}
			err = uploadPackedGo(context.Background(), client, server.URL, "workspace", "repository", time.Now(), packed, strings.NewReader("synthetic zip"), &output)
			if err != nil || uploads != test.wantUpload || publishes != test.wantPublish || !strings.Contains(output.String(), test.wantText) || !strings.Contains(output.String(), session) {
				t.Fatalf("result err=%v uploads=%d publishes=%d output=%q", err, uploads, publishes, output.String())
			}
		})
	}
}

func TestPublishRequestNeverExposesResponseBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "synthetic-secret")
	}))
	defer server.Close()
	_, err := publishRequest(context.Background(), server.Client(), server.URL, http.MethodGet, "/", "", nil, false)
	if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatalf("unsafe registry error: %v", err)
	}
}

func TestPublicationFinalizeRequiresCurrentApproval(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      string
		review      string
		invalidated bool
		wantPublish bool
		wantError   bool
	}{
		{"pending", "uploaded", "awaiting_review", false, false, true},
		{"approved", "uploaded", "approved", false, true, false},
		{"invalidated", "uploaded", "approved", true, false, true},
		{"already published", "published", "completed", false, false, false},
		{"unknown", "uploaded", "unexpected", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publishes := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					_, _ = fmt.Fprintf(w, `{"status":%q,"review_state":%q,"recovery_invalidated":%t}`, tc.status, tc.review, tc.invalidated)
					return
				}
				publishes++
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			client := server.Client()
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			client.Jar = jar
			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(req.URL, []*http.Cookie{{Name: "__Host-registry-csrf", Value: "synthetic-csrf", Path: "/", Secure: true}})
			var out bytes.Buffer
			err = publicationAction(context.Background(), client, server.URL, "/session", "finalize", &out)
			if (err != nil) != tc.wantError || (publishes != 0) != tc.wantPublish {
				t.Fatalf("finalize err=%v publishes=%d", err, publishes)
			}
		})
	}
}

func TestRegistryClientRefusesRedirect(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client, err := newRegistryClient()
	if err != nil {
		t.Fatal(err)
	}
	client.Transport = server.Client().Transport
	defer client.CloseIdleConnections()
	_, err = loginForPublish(context.Background(), client, server.URL, "synthetic", "synthetic-password")
	if err == nil || targetRequests.Load() != 0 {
		t.Fatalf("redirect was followed: err=%v requests=%d", err, targetRequests.Load())
	}
}
