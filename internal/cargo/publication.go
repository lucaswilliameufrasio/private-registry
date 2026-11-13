package cargo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// ValidateStagedPublication binds the staged bytes to the received framing and
// runs the experimental archive and metadata checks together. The caller must
// keep the staged file immutable throughout validation and subsequent storage.
// This does not authorize, reserve, review, persist or publish a crate; version
// requirement semantics and other documented checks remain incomplete.
func ValidateStagedPublication(ctx context.Context, frame PublishFrame, archive io.Reader, limits ArchiveLimits, currentIndex, defaultIndex string) (IndexEntry, error) {
	if archive == nil || frame.Size < 1 || frame.Size > limits.MaxCompressedBytes {
		return IndexEntry{}, errors.New("Cargo staged archive parameters are invalid")
	}
	entry, err := ProjectIndex(frame.Metadata, frame.SHA256)
	if err != nil {
		return IndexEntry{}, err
	}
	if _, err := SparseIndexPath(entry.Name); err != nil {
		return IndexEntry{}, err
	}
	hash := sha256.New()
	reader := &countedReader{source: io.TeeReader(archive, hash)}
	contents, err := InspectArchive(ctx, reader, entry.Name, entry.Version, limits)
	if err != nil {
		return IndexEntry{}, err
	}
	if reader.count != frame.Size || hex.EncodeToString(hash.Sum(nil)) != frame.SHA256 {
		return IndexEntry{}, errors.New("Cargo staged archive does not match received bytes")
	}
	if err := ValidateManifestIdentity(contents.Manifest, entry.Name, entry.Version); err != nil {
		return IndexEntry{}, err
	}
	if err := ValidateManifestFeatures(contents.Manifest, frame.Metadata); err != nil {
		return IndexEntry{}, err
	}
	if err := ValidateManifestIndexFields(contents.Manifest, frame.Metadata); err != nil {
		return IndexEntry{}, err
	}
	if err := ValidateManifestDependencies(contents.Manifest, frame.Metadata, currentIndex, defaultIndex); err != nil {
		return IndexEntry{}, err
	}
	return entry, nil
}

type countedReader struct {
	source io.Reader
	count  int64
}

func (r *countedReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.count += int64(n)
	return n, err
}
