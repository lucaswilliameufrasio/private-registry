package npm

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

func makeArchive(t *testing.T, entries []archiveEntry) []byte {
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
	manifest := `{"name":"@fixture/pkg","version":"1.0.0","versions":"custom"}`
	entries := []archiveEntry{{"package/package.json", tar.TypeReg, manifest}, {"package/src/index.js", tar.TypeReg, "export default 1;"}}
	valid := makeArchive(t, entries)
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
	limits := ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 10, MaxManifestBytes: 1024}
	result, err := InspectArchive(ctx, bytes.NewReader(valid), "@fixture/pkg", "1.0.0", limits)
	if err != nil || string(result.Manifest) != manifest || result.Entries != 2 {
		t.Fatalf("archive inspection failed: %+v err=%v", result, err)
	}
	checksum := bytes.Clone(valid)
	checksum[len(checksum)-8] ^= 0x80
	for _, tc := range []struct {
		name   string
		data   []byte
		limits ArchiveLimits
	}{
		{"truncated", valid[:len(valid)-1], limits},
		{"bad checksum", checksum, limits},
		{"trailing bytes", append(bytes.Clone(valid), 1), limits},
		{"gzip member", append(bytes.Clone(valid), valid...), limits},
		{"data after tar", trailingTar.Bytes(), limits},
		{"duplicate", makeArchive(t, append(entries, entries[0])), limits},
		{"case collision", makeArchive(t, append(entries, archiveEntry{"package/SRC/INDEX.JS", tar.TypeReg, "x"})), limits},
		{"file before child", makeArchive(t, append(entries, archiveEntry{"package/other", tar.TypeReg, "x"}, archiveEntry{"package/other/child", tar.TypeReg, "x"})), limits},
		{"file after child", makeArchive(t, append(entries, archiveEntry{"package/other/child", tar.TypeReg, "x"}, archiveEntry{"package/other", tar.TypeReg, "x"})), limits},
		{"traversal", makeArchive(t, append(entries, archiveEntry{"package/../outside", tar.TypeReg, "x"})), limits},
		{"wrong root", makeArchive(t, append(entries, archiveEntry{"other/file", tar.TypeReg, "x"})), limits},
		{"symlink", makeArchive(t, append(entries, archiveEntry{"package/link", tar.TypeSymlink, ""})), limits},
		{"missing manifest", makeArchive(t, entries[1:]), limits},
		{"compressed limit", valid, ArchiveLimits{int64(len(valid) - 1), 1 << 20, 10, 1024}},
		{"uncompressed limit", valid, ArchiveLimits{1 << 20, 512, 10, 1024}},
		{"entry count", valid, ArchiveLimits{1 << 20, 1 << 20, 1, 1024}},
		{"manifest limit", valid, ArchiveLimits{1 << 20, 1 << 20, 10, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := InspectArchive(ctx, bytes.NewReader(tc.data), "@fixture/pkg", "1.0.0", tc.limits); err == nil {
				t.Fatal("invalid archive accepted")
			}
		})
	}
	if _, err := InspectArchive(ctx, bytes.NewReader(valid), "@fixture/pkg", "2.0.0", limits); err == nil {
		t.Fatal("mismatched manifest version accepted")
	}
}
