package cargo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"
	"time"
)

type archiveEntry struct {
	name string
	kind byte
	data string
}

func testArchive(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		header := &tar.Header{Name: entry.name, Mode: 0o600, Typeflag: entry.kind, Size: int64(len(entry.data))}
		if entry.kind == tar.TypeSymlink {
			header.Linkname = "target"
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestInspectArchive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	manifest := "[package]\nname = \"synthetic\"\nversion = \"1.0.0\"\n"
	entries := []archiveEntry{{"synthetic-1.0.0/Cargo.toml", tar.TypeReg, manifest}, {"synthetic-1.0.0/src/lib.rs", tar.TypeReg, "pub fn value() {}\n"}}
	valid := testArchive(t, entries)
	badChecksum := bytes.Clone(valid)
	badChecksum[len(badChecksum)-8] ^= 0x80
	reader, err := gzip.NewReader(bytes.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	uncompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	var trailingTar bytes.Buffer
	compressor := gzip.NewWriter(&trailingTar)
	if _, err := compressor.Write(append(uncompressed, 'x')); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	limits := ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxFiles: 10, MaxManifestBytes: 1024}
	result, err := InspectArchive(ctx, bytes.NewReader(valid), "synthetic", "1.0.0", limits)
	if err != nil || string(result.Manifest) != manifest || result.Files != 2 {
		t.Fatalf("archive inspection failed: %+v err=%v", result, err)
	}
	for _, tc := range []struct {
		name   string
		data   []byte
		limits ArchiveLimits
	}{
		{"truncated gzip", valid[:len(valid)-1], limits},
		{"corrupt gzip checksum", badChecksum, limits},
		{"trailing bytes", append(bytes.Clone(valid), 1), limits},
		{"concatenated gzip member", append(bytes.Clone(valid), valid...), limits},
		{"data after tar", trailingTar.Bytes(), limits},
		{"duplicate paths", testArchive(t, append(entries, entries[0])), limits},
		{"case collision", testArchive(t, append(entries, archiveEntry{"synthetic-1.0.0/SRC/LIB.RS", tar.TypeReg, "x"})), limits},
		{"file before child", testArchive(t, append(entries, archiveEntry{"synthetic-1.0.0/other", tar.TypeReg, "x"}, archiveEntry{"synthetic-1.0.0/other/child", tar.TypeReg, "x"})), limits},
		{"file after child", testArchive(t, append(entries, archiveEntry{"synthetic-1.0.0/other/child", tar.TypeReg, "x"}, archiveEntry{"synthetic-1.0.0/other", tar.TypeReg, "x"})), limits},
		{"traversal", testArchive(t, append(entries, archiveEntry{"synthetic-1.0.0/../escape", tar.TypeReg, "x"})), limits},
		{"wrong root", testArchive(t, append(entries, archiveEntry{"other-1.0.0/file", tar.TypeReg, "x"})), limits},
		{"backslash path", testArchive(t, append(entries, archiveEntry{"synthetic-1.0.0/src\\evil", tar.TypeReg, "x"})), limits},
		{"absolute path", testArchive(t, append(entries, archiveEntry{"/synthetic-1.0.0/file", tar.TypeReg, "x"})), limits},
		{"symlink", testArchive(t, append(entries, archiveEntry{"synthetic-1.0.0/link", tar.TypeSymlink, ""})), limits},
		{"missing manifest", testArchive(t, entries[1:]), limits},
		{"compressed limit", valid, ArchiveLimits{int64(len(valid) - 1), 1 << 20, 10, 1024}},
		{"uncompressed limit", valid, ArchiveLimits{1 << 20, 512, 10, 1024}},
		{"file count", valid, ArchiveLimits{1 << 20, 1 << 20, 1, 1024}},
		{"manifest limit", valid, ArchiveLimits{1 << 20, 1 << 20, 10, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := InspectArchive(ctx, bytes.NewReader(tc.data), "synthetic", "1.0.0", tc.limits); err == nil {
				t.Fatal("invalid archive accepted")
			}
		})
	}
}
