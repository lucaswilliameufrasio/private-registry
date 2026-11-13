package email

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var updateManifest = flag.Bool("update-sabia-manifest", false, "rewrite sabia/templates.json")

func recoveryMessage() Message {
	return Message{Template: TemplateRecovery, To: "ana@example.com", Data: map[string]string{"display_name": "Ana <script>", "link": "https://registry.example/ui/#/recover/prrst_x", "expires_at": "2026-11-13 12:00"}}
}

func TestValidateRejectsUnsafeMessages(t *testing.T) {
	good := recoveryMessage()
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Message){
		"unknown template": func(m *Message) { m.Template = "registry.unknown" },
		"bad recipient":    func(m *Message) { m.To = "Ana <ana@example.com>" },
		"header injection": func(m *Message) { m.To = "ana@example.com\r\nBcc: x@example.com" },
		"missing variable": func(m *Message) { delete(m.Data, "expires_at") },
		"extra variable":   func(m *Message) { m.Data["other"] = "x" },
		"control char":     func(m *Message) { m.Data["display_name"] = "Ana\nBcc: x" },
		"non-http link":    func(m *Message) { m.Data["link"] = "javascript:alert(1)" },
		"empty value":      func(m *Message) { m.Data["display_name"] = "" },
	}
	for name, mutate := range cases {
		message := recoveryMessage()
		mutate(&message)
		if err := message.Validate(); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRenderEscapesHTMLOnly(t *testing.T) {
	rendered, err := Render(recoveryMessage())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered.HTML, "<script>") || !strings.Contains(rendered.HTML, "Ana &lt;script&gt;") {
		t.Fatal("HTML body did not escape the display name")
	}
	if !strings.Contains(rendered.Text, "Ana <script>") || strings.Contains(rendered.Text, "{{") || strings.Contains(rendered.HTML, "{{") || rendered.Subject == "" {
		t.Fatalf("unexpected rendering: %+v", rendered)
	}
}

// Every template declares exactly the variables its sources use, and the
// committed Sabiá manifest is generated from these sources.
func TestTemplatesAndSabiaManifest(t *testing.T) {
	for _, item := range definitions {
		used := map[string]bool{}
		for _, source := range []string{item.Subject, item.HTML, item.Text} {
			for _, match := range placeholder.FindAllStringSubmatch(source, -1) {
				used[match[1]] = true
			}
		}
		if len(used) != len(item.Vars) {
			t.Errorf("%s uses %d variables but declares %d", item.Key, len(used), len(item.Vars))
		}
		data := map[string]string{}
		for _, v := range item.Vars {
			if !used[v.Key] {
				t.Errorf("%s declares unused %s", item.Key, v.Key)
			}
			data[v.Key] = v.Example
		}
		if _, err := Render(Message{Template: item.Key, To: "a@example.com", Data: data}); err != nil {
			t.Errorf("%s examples do not render: %v", item.Key, err)
		}
	}
	manifest, err := SabiaManifest()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "sabia", "templates.json")
	if *updateManifest {
		if err := os.WriteFile(path, manifest, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, manifest) {
		t.Fatal("sabia/templates.json is stale: run go test ./internal/email -run TestTemplatesAndSabiaManifest -update-sabia-manifest")
	}
}

type recordedRequest struct {
	path, auth, key string
	body            map[string]any
}

func fakeProvider(t *testing.T, statuses ...int) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	var mu sync.Mutex
	var requests []recordedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var body map[string]any
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &body)
		requests = append(requests, recordedRequest{path: r.URL.Path, auth: r.Header.Get("Authorization"), key: r.Header.Get("Idempotency-Key"), body: body})
		status := statuses[min(len(requests)-1, len(statuses)-1)]
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "7")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error_code":"TEMPLATE_NOT_FOUND","name":"validation_error","message":"ana@example.com"}`))
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

func TestSabiaContract(t *testing.T) {
	server, requests := fakeProvider(t, http.StatusAccepted, http.StatusTooManyRequests, http.StatusNotFound)
	sender, err := NewSabia(server.URL+"/", "sb_live_test", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := sender.Send(ctx, recoveryMessage(), "email:recovery:1"); err != nil {
		t.Fatal(err)
	}
	got := (*requests)[0]
	data, _ := got.body["data"].(map[string]any)
	if got.path != "/v1/messages" || got.auth != "Bearer sb_live_test" || got.key != "email:recovery:1" || got.body["channel"] != "email" || got.body["template"] != string(TemplateRecovery) || got.body["locale"] != Locale || got.body["to"] != "ana@example.com" || data["link"] == nil || len(got.body) != 6 {
		t.Fatalf("unexpected Sabiá request: %+v", got)
	}
	err = sender.Send(ctx, recoveryMessage(), "email:recovery:1")
	if IsPermanent(err) || retryAfter(err) != 7*time.Second {
		t.Fatalf("429 must be retried after Retry-After: %v", err)
	}
	err = sender.Send(ctx, recoveryMessage(), "email:recovery:1")
	if !IsPermanent(err) || !strings.Contains(err.Error(), "TEMPLATE_NOT_FOUND") || strings.Contains(err.Error(), "ana@") {
		t.Fatalf("404 must be permanent and must not echo the body: %v", err)
	}
}

func TestResendCompatibleContract(t *testing.T) {
	server, requests := fakeProvider(t, http.StatusOK, http.StatusServiceUnavailable, http.StatusUnprocessableEntity)
	sender, err := NewResend("millionsend", server.URL, "ms_test", "Registry <registry@example.com>", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := sender.Send(ctx, recoveryMessage(), "email:recovery:2"); err != nil {
		t.Fatal(err)
	}
	got := (*requests)[0]
	to, _ := got.body["to"].([]any)
	if got.path != "/emails" || got.auth != "Bearer ms_test" || got.key != "email:recovery:2" || got.body["from"] != "Registry <registry@example.com>" || len(to) != 1 || to[0] != "ana@example.com" || got.body["subject"] == "" || !strings.Contains(got.body["html"].(string), "&lt;script&gt;") || got.body["text"] == "" {
		t.Fatalf("unexpected Resend request: %+v", got)
	}
	if err := sender.Send(ctx, recoveryMessage(), "email:recovery:2"); err == nil || IsPermanent(err) {
		t.Fatalf("503 must be retried: %v", err)
	}
	if err := sender.Send(ctx, recoveryMessage(), "email:recovery:2"); !IsPermanent(err) {
		t.Fatalf("422 must be permanent: %v", err)
	}
	if _, err := NewResend("resend", server.URL, "re_test", "not an address", server.Client()); err == nil {
		t.Fatal("accepted an invalid sender")
	}
}

type staticDialer struct{ address, host string }

func (d staticDialer) Dial(ctx context.Context) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.address)
}
func (d staticDialer) Host() string { return d.host }

func TestSMTPRequiresTLSOutsideLoopback(t *testing.T) {
	if _, err := NewSMTP(staticDialer{host: "smtp.example.com"}, SMTPOptions{Security: SMTPPlain, From: "registry@example.com"}); err == nil {
		t.Fatal("plain SMTP accepted for a remote host")
	}
	if _, err := NewSMTP(staticDialer{host: "127.0.0.1"}, SMTPOptions{Security: SMTPPlain, From: "registry@example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSMTP(staticDialer{host: "smtp.example.com"}, SMTPOptions{Security: SMTPStartTLS, From: "registry@example.com", Username: "user"}); err == nil {
		t.Fatal("accepted a username without a password")
	}
}

func TestSMTPComposeIsSafe(t *testing.T) {
	sender, err := NewSMTP(staticDialer{host: "127.0.0.1"}, SMTPOptions{Security: SMTPPlain, From: "Registry <registry@example.com>"})
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := Render(recoveryMessage())
	if err != nil {
		t.Fatal(err)
	}
	first, err := sender.compose("ana@example.com", rendered, "email:recovery:3")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := sender.compose("ana@example.com", rendered, "email:recovery:3")
	id := func(body []byte) string {
		for _, line := range strings.Split(string(body), "\r\n") {
			if strings.HasPrefix(line, "Message-ID: ") {
				return line
			}
		}
		return ""
	}
	if id(first) == "" || id(first) != id(second) || !strings.Contains(id(first), "@example.com>") {
		t.Fatal("Message-ID must be stable for one idempotency key")
	}
	if !strings.Contains(string(first), "Subject: =?utf-8?q?") || !strings.Contains(string(first), "multipart/alternative") {
		t.Fatalf("unexpected headers:\n%s", first)
	}
}
