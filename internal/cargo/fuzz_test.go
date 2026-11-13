package cargo

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func FuzzReadPublishFrame(f *testing.F) {
	f.Add(frame([]byte(`{"name":"fixture"}`), []byte("crate")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var staged bytes.Buffer
		result, err := ReadPublishFrame(ctx, bytes.NewReader(data), &staged, 4096, 65536)
		if staged.Len() > 65536 {
			t.Fatal("framing wrote beyond archive limit")
		}
		if err == nil && (result.Size != int64(staged.Len()) || len(result.Metadata) == 0 || len(result.Metadata) > 4096) {
			t.Fatal("successful frame violated declared limits")
		}
	})
}

func FuzzCheckMetadataJSON(f *testing.F) {
	f.Add([]byte(`{"name":"fixture","deps":[]}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_ = CheckMetadataJSON(data)
	})
}

func FuzzValidateManifestIndexFields(f *testing.F) {
	f.Add([]byte("[package]\nlinks = \"fixture\"\nrust-version = \"1.80\"\n"), []byte(`{"links":"fixture","rust_version":"1.80"}`))
	f.Add([]byte("[package]\n"), []byte(`{}`))
	f.Fuzz(func(t *testing.T, manifest, metadata []byte) {
		if len(manifest) > 1<<20 || len(metadata) > 1<<20 {
			t.Skip()
		}
		_ = ValidateManifestIndexFields(manifest, metadata)
	})
}

func FuzzInspectArchive(f *testing.F) {
	f.Add([]byte("not gzip"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		result, err := InspectArchive(ctx, bytes.NewReader(data), "fixture", "1.0.0", ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxFiles: 100, MaxManifestBytes: 4096})
		if err == nil && (result.Files < 1 || result.Files > 100 || len(result.Manifest) == 0 || len(result.Manifest) > 4096) {
			t.Fatal("successful archive inspection violated declared limits")
		}
	})
}
