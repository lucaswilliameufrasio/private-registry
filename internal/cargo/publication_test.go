package cargo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestValidateStagedPublication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	archive := testArchive(t, []archiveEntry{{"fixture-1.0.0/Cargo.toml", 0, "[package]\nname = \"fixture\"\nversion = \"1.0.0\"\n"}})
	digest := sha256.Sum256(archive)
	frame := PublishFrame{Metadata: []byte(`{"name":"fixture","vers":"1.0.0","deps":[],"features":{}}`), Size: int64(len(archive)), SHA256: hex.EncodeToString(digest[:])}
	limits := ArchiveLimits{MaxCompressedBytes: 1 << 20, MaxUncompressedBytes: 1 << 20, MaxFiles: 100, MaxManifestBytes: 4096}
	validate := func(input PublishFrame, data []byte) error {
		_, err := ValidateStagedPublication(ctx, input, bytes.NewReader(data), limits, "sparse+https://registry.example/index/", "https://github.com/rust-lang/crates.io-index")
		return err
	}
	if err := validate(frame, archive); err != nil {
		t.Fatal(err)
	}
	wrongDigest := frame
	wrongDigest.SHA256 = hex.EncodeToString(make([]byte, sha256.Size))
	if err := validate(wrongDigest, archive); err == nil {
		t.Fatal("staged archive with a different digest was accepted")
	}
	wrongSize := frame
	wrongSize.Size++
	if err := validate(wrongSize, archive); err == nil {
		t.Fatal("staged archive with a different size was accepted")
	}
	wrongIdentity := frame
	wrongIdentity.Metadata = []byte(`{"name":"other","vers":"1.0.0","deps":[],"features":{}}`)
	if err := validate(wrongIdentity, archive); err == nil {
		t.Fatal("archive with a different manifest identity was accepted")
	}
	wrongFeatures := frame
	wrongFeatures.Metadata = []byte(`{"name":"fixture","vers":"1.0.0","deps":[],"features":{"unexpected":[]}}`)
	if err := validate(wrongFeatures, archive); err == nil {
		t.Fatal("archive with different feature metadata was accepted")
	}
	wrongLinks := frame
	wrongLinks.Metadata = []byte(`{"name":"fixture","vers":"1.0.0","deps":[],"features":{},"links":"unexpected"}`)
	if err := validate(wrongLinks, archive); err == nil {
		t.Fatal("archive with different links metadata was accepted")
	}
	if _, err := ValidateStagedPublication(ctx, frame, bytes.NewReader(archive), limits, "", "https://github.com/rust-lang/crates.io-index"); err == nil {
		t.Fatal("archive without trusted registry context was accepted")
	}
	withTrailing := append(bytes.Clone(archive), 0)
	if err := validate(frame, withTrailing); err == nil {
		t.Fatal("archive with trailing staged bytes was accepted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := ValidateStagedPublication(canceled, frame, bytes.NewReader(archive), limits, "sparse+https://registry.example/index/", "https://github.com/rust-lang/crates.io-index"); err == nil {
		t.Fatal("archive validation accepted a canceled context")
	}
}
