package npm

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReadPublishDocument(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body := `{"_id":"@fixture/pkg","name":"@fixture/pkg","versions":{"1.0.0":{"name":"@fixture/pkg","version":"1.0.0"}},"dist-tags":{"latest":"1.0.0"},"_attachments":{"pkg.tgz":{"data":"c3ludGhldGlj","length":9}}}`
	var staged bytes.Buffer
	result, err := ReadPublishDocument(ctx, strings.NewReader(body), &staged, "@fixture/pkg", 4096, 1024)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512([]byte("synthetic"))
	if result.Name != "@fixture/pkg" || result.Version != "1.0.0" || result.Tags["latest"] != "1.0.0" || result.Size != 9 || staged.String() != "synthetic" || result.Integrity != "sha512-"+base64.StdEncoding.EncodeToString(digest[:]) {
		t.Fatal("npm publication metadata or staged content differs")
	}
	for _, tc := range []struct {
		name string
		body string
	}{
		{"duplicate", strings.Replace(body, `"name":"@fixture/pkg"`, `"name":"@fixture/pkg","name":"other"`, 1)},
		{"escaped duplicate", strings.Replace(body, `"name":"@fixture/pkg"`, `"name":"@fixture/pkg","\u006eame":"other"`, 1)},
		{"case variant", strings.Replace(body, `"name":"@fixture/pkg"`, `"name":"@fixture/pkg","Name":"other"`, 1)},
		{"manifest case variant", strings.Replace(body, `"version":"1.0.0"`, `"version":"1.0.0","Version":"2.0.0"`, 1)},
		{"attachment case variant", strings.Replace(body, `"length":9`, `"length":9,"Length":8`, 1)},
		{"unpaired surrogate", strings.Replace(body, `"latest"`, `"\ud800"`, 1)},
		{"unpaired low surrogate", strings.Replace(body, `"latest"`, `"\udc00"`, 1)},
		{"length mismatch", strings.Replace(body, `"length":9`, `"length":8`, 1)},
		{"bad base64", strings.Replace(body, "c3ludGhldGlj", "c3ludGhl%Glj", 1)},
		{"trailing object", body + `{}`},
		{"wrong version", strings.Replace(body, `"version":"1.0.0"`, `"version":"2.0.0"`, 1)},
		{"invalid version", strings.ReplaceAll(body, "1.0.0", "1.0")},
		{"numeric overflow", strings.ReplaceAll(body, "1.0.0", "9007199254740992.0.0")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadPublishDocument(ctx, strings.NewReader(tc.body), io.Discard, "@fixture/pkg", 4096, 1024); err == nil {
				t.Fatal("invalid npm publication accepted")
			}
		})
	}
	if _, err := ReadPublishDocument(ctx, strings.NewReader(body), io.Discard, "@fixture/pkg", int64(len(body)-1), 1024); err == nil {
		t.Fatal("oversized document accepted")
	}
	if _, err := ReadPublishDocument(ctx, strings.NewReader(body), io.Discard, "@fixture/pkg", 4096, 8); err == nil {
		t.Fatal("oversized attachment accepted")
	}
	if _, err := ReadPublishDocument(context.Background(), strings.NewReader(body), io.Discard, "@fixture/pkg", 4096, 1024); err == nil {
		t.Fatal("missing deadline accepted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := ReadPublishDocument(canceled, strings.NewReader(body), io.Discard, "@fixture/pkg", 4096, 1024); err == nil {
		t.Fatal("canceled document accepted")
	}
	if _, err := ReadPublishDocument(ctx, strings.NewReader(body), failWriter{}, "@fixture/pkg", 4096, 1024); err == nil {
		t.Fatal("failed staging accepted")
	}
}

func TestJSONSurrogateEscapes(t *testing.T) {
	for _, tc := range []struct {
		data  string
		valid bool
	}{
		{`{"x":"\ud800"}`, false},
		{`{"x":"\udc00"}`, false},
		{`{"x":"\ud83d\ude80"}`, true},
		{`{"x":"\\ud800"}`, true},
	} {
		if err := checkJSON([]byte(tc.data)); (err == nil) != tc.valid {
			t.Fatalf("valid=%t err=%v", tc.valid, err)
		}
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic staging failure")
}
