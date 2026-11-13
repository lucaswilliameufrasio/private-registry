package npm

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"
)

// ValidateStagedPublication rechecks the staged archive's size and digest and
// compares its manifest against the published metadata. The caller must keep
// staging immutable through storage. It does not authorize, reserve, review,
// publish or validate all npm name, version, tag and dependency semantics.
func ValidateStagedPublication(ctx context.Context, publication PublishDocument, source io.Reader, limits ArchiveLimits) error {
	if source == nil || publication.Size < 1 || publication.Size > limits.MaxCompressedBytes {
		return errors.New("npm staged archive parameters are invalid")
	}
	hash := sha512.New()
	reader := &countedReader{source: io.TeeReader(source, hash)}
	contents, err := InspectArchive(ctx, reader, publication.Name, publication.Version, limits)
	if err != nil {
		return err
	}
	if reader.count != publication.Size || "sha512-"+base64.StdEncoding.EncodeToString(hash.Sum(nil)) != publication.Integrity {
		return errors.New("npm staged archive does not match received bytes")
	}
	return ValidateManifestMetadata(publication.Manifest, contents.Manifest)
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
