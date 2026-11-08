package npm

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"testing"
	"time"
)

func TestValidateStagedPublication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	manifest := `{"name":"@fixture/pkg","version":"1.0.0","exports":{".":"./index.js"}}`
	archive := makeArchive(t, []archiveEntry{{"package/package.json", tar.TypeReg, manifest}})
	digest := sha512.Sum512(archive)
	publication := PublishDocument{Name: "@fixture/pkg", Version: "1.0.0", Manifest: []byte(manifest), Size: int64(len(archive)), Integrity: "sha512-" + base64.StdEncoding.EncodeToString(digest[:])}
	limits := ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxEntries: 100, MaxManifestBytes: 4096}
	validate := func(item PublishDocument, data []byte) error {
		return ValidateStagedPublication(ctx, item, bytes.NewReader(data), limits)
	}
	if err := validate(publication, archive); err != nil {
		t.Fatal(err)
	}
	wrongSize := publication
	wrongSize.Size++
	if err := validate(wrongSize, archive); err == nil {
		t.Fatal("wrong archive size accepted")
	}
	wrongDigest := publication
	wrongDigest.Integrity = "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, sha512.Size))
	if err := validate(wrongDigest, archive); err == nil {
		t.Fatal("wrong archive digest accepted")
	}
	wrongMetadata := publication
	wrongMetadata.Manifest = []byte(`{"name":"@fixture/pkg","version":"1.0.0","exports":{".":"./other.js"}}`)
	if err := validate(wrongMetadata, archive); err == nil {
		t.Fatal("different publish metadata accepted")
	}
	if err := validate(publication, append(bytes.Clone(archive), 0)); err == nil {
		t.Fatal("trailing staged bytes accepted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := ValidateStagedPublication(canceled, publication, bytes.NewReader(archive), limits); err == nil {
		t.Fatal("canceled validation accepted")
	}
}
