package npm

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func FuzzReadPublishDocument(f *testing.F) {
	f.Add([]byte(`{"_id":"fixture","name":"fixture","versions":{"1.0.0":{"name":"fixture","version":"1.0.0"}},"_attachments":{"fixture.tgz":{"data":"eA==","length":1}}}`))
	f.Add([]byte(`{"name":"a","name":"b"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var staged bytes.Buffer
		result, err := ReadPublishDocument(ctx, bytes.NewReader(input), &staged, "fixture", 1<<20, 1<<16)
		if staged.Len() > 1<<16 || (err == nil && (result.Size != int64(staged.Len()) || result.Size < 1)) {
			t.Fatal("npm framing exceeded its declared bounds")
		}
	})
}

func FuzzInspectArchive(f *testing.F) {
	f.Add([]byte("not a gzip"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		result, err := InspectArchive(ctx, bytes.NewReader(input), "fixture", "1.0.0", ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 100, MaxManifestBytes: 4096})
		if err == nil && (result.Entries < 1 || result.Entries > 100 || len(result.Manifest) < 1 || len(result.Manifest) > 4096) {
			t.Fatal("npm archive inspection exceeded its declared bounds")
		}
	})
}

func FuzzManifestMetadata(f *testing.F) {
	f.Add([]byte(`{"name":"fixture","version":"1.0.0"}`), []byte(`{"name":"fixture","version":"1.0.0"}`))
	f.Fuzz(func(t *testing.T, published, archived []byte) {
		if len(published) > 1<<20 || len(archived) > 1<<20 {
			t.Skip()
		}
		_ = ValidateManifestMetadata(published, archived)
	})
}
