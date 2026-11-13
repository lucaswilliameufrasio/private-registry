package pub

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

type fixtureEntry struct {
	name string
	kind byte
	body string
}

func fixtureArchive(t *testing.T, entries []fixtureEntry) []byte {
	t.Helper()
	var result bytes.Buffer
	gz := gzip.NewWriter(&result)
	w := tar.NewWriter(gz)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Typeflag: entry.kind, Mode: 0o600, Size: int64(len(entry.body))}
		if entry.kind == tar.TypeSymlink {
			header.Linkname = "target"
		}
		if err := w.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}

func TestInspectArchive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	limits := ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 10, MaxManifestBytes: 1024}
	manifest := fixtureEntry{name: "pubspec.yaml", kind: tar.TypeReg, body: "name: fixture\nversion: 1.0.0\n"}
	tests := []struct {
		name    string
		entries []fixtureEntry
		valid   bool
	}{
		{"valid", []fixtureEntry{manifest, {name: "lib/main.dart", kind: tar.TypeReg, body: "fixture"}}, true},
		{"missing manifest", []fixtureEntry{{name: "lib/main.dart", kind: tar.TypeReg, body: "fixture"}}, false},
		{"traversal", []fixtureEntry{manifest, {name: "../escape", kind: tar.TypeReg, body: "x"}}, false},
		{"absolute", []fixtureEntry{manifest, {name: "/escape", kind: tar.TypeReg, body: "x"}}, false},
		{"case collision", []fixtureEntry{manifest, {name: "PUBSPEC.yaml", kind: tar.TypeReg, body: "x"}}, false},
		{"symlink", []fixtureEntry{manifest, {name: "link", kind: tar.TypeSymlink}}, false},
		{"file parent", []fixtureEntry{manifest, {name: "lib", kind: tar.TypeReg, body: "x"}, {name: "lib/a", kind: tar.TypeReg, body: "x"}}, false},
		{"parent after child", []fixtureEntry{manifest, {name: "lib/a", kind: tar.TypeReg, body: "x"}, {name: "lib", kind: tar.TypeReg, body: "x"}}, false},
		{"embedded traversal", []fixtureEntry{manifest, {name: "lib/../other", kind: tar.TypeReg, body: "x"}}, false},
		{"backslash", []fixtureEntry{manifest, {name: `lib\other`, kind: tar.TypeReg, body: "x"}}, false},
		{"duplicate manifest", []fixtureEntry{manifest, manifest}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contents, err := InspectArchive(ctx, bytes.NewReader(fixtureArchive(t, tt.entries)), limits)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v error=%v", tt.valid, err)
			}
			if tt.valid && string(contents.Manifest) != manifest.body {
				t.Fatal("manifest differs")
			}
		})
	}
	data := fixtureArchive(t, []fixtureEntry{manifest})
	if _, err := InspectArchive(ctx, bytes.NewReader(append(data, 1)), limits); err == nil {
		t.Fatal("accepted trailing compressed data")
	}
	second := fixtureArchive(t, []fixtureEntry{manifest})
	if _, err := InspectArchive(ctx, bytes.NewReader(append(data, second...)), limits); err == nil {
		t.Fatal("accepted concatenated gzip members")
	}
	limits.MaxManifestBytes = 2
	if _, err := InspectArchive(ctx, bytes.NewReader(data), limits); err == nil {
		t.Fatal("accepted oversized manifest")
	}
}

func TestArchiveManifestIdentityValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	limits := ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 10, MaxManifestBytes: 1024}
	data := fixtureArchive(t, []fixtureEntry{{name: "pubspec.yaml", kind: tar.TypeReg, body: "name: fixture\nversion: 1.0.0\n"}})
	contents, err := InspectArchive(ctx, bytes.NewReader(data), limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePubspec(contents.Manifest, "fixture", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePubspec(contents.Manifest, "fixture", "2.0.0"); err == nil {
		t.Fatal("archive manifest accepted mismatched publication identity")
	}
	validated, err := InspectPackage(ctx, bytes.NewReader(data), "fixture", "1.0.0", limits)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if validated.Size != int64(len(data)) || validated.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("validated archive digest or size differs")
	}
	if _, err := InspectPackage(ctx, bytes.NewReader(data), "fixture", "2.0.0", limits); err == nil {
		t.Fatal("package inspection accepted mismatched identity")
	}
}

func TestInspectArchiveLimitsAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	limits := ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 10, MaxManifestBytes: 1024}
	data := fixtureArchive(t, []fixtureEntry{
		{name: "pubspec.yaml", kind: tar.TypeReg, body: "name: fixture\nversion: 1.0.0\n"},
		{name: "lib/main.dart", kind: tar.TypeReg, body: "content"},
	})
	if _, err := InspectArchive(context.Background(), bytes.NewReader(data), limits); err == nil {
		t.Fatal("accepted inspection without deadline")
	}
	cancelled, cancelNow := context.WithCancel(ctx)
	cancelNow()
	if _, err := InspectArchive(cancelled, bytes.NewReader(data), limits); err == nil {
		t.Fatal("accepted cancelled inspection")
	}
	entryLimit := limits
	entryLimit.MaxEntries = 1
	if _, err := InspectArchive(ctx, bytes.NewReader(data), entryLimit); err == nil {
		t.Fatal("accepted too many entries")
	}
	compressedLimit := limits
	compressedLimit.MaxCompressedBytes = int64(len(data) - 1)
	if _, err := InspectArchive(ctx, bytes.NewReader(data), compressedLimit); err == nil {
		t.Fatal("accepted oversized compressed archive")
	}
	uncompressedLimit := limits
	uncompressedLimit.MaxUncompressedBytes = 64
	if _, err := InspectArchive(ctx, bytes.NewReader(data), uncompressedLimit); err == nil {
		t.Fatal("accepted oversized uncompressed archive")
	}
	corrupted := append([]byte(nil), data...)
	corrupted[len(corrupted)-1] ^= 1
	if _, err := InspectArchive(ctx, bytes.NewReader(corrupted), limits); err == nil {
		t.Fatal("accepted corrupted gzip checksum")
	}
}

func FuzzInspectArchive(f *testing.F) {
	f.Add([]byte("not a gzip archive"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		limits := ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 2 << 20, MaxEntries: 100, MaxManifestBytes: 1 << 16}
		_, _ = InspectPackage(ctx, bytes.NewReader(data), "fixture", "1.0.0", limits)
	})
}
