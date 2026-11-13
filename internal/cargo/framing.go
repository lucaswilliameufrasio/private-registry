// Package cargo contains protocol boundaries for the experimental Cargo adapter.
// Framing validation alone does not authorize, validate, or publish a crate.
package cargo

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
)

// PublishFrame describes bytes copied from the Cargo publish wire format. The
// caller must validate metadata and the crate archive independently before use.
type PublishFrame struct {
	Metadata []byte
	Size     int64
	SHA256   string
}

// ReadPublishFrame reads Cargo's little-endian metadata length, metadata,
// archive length, and archive. Output may be partial on any error and must be
// discarded. Callers must authorize before invoking this function, enforce
// aggregate concurrency and disk limits, and supply a deadline and an input
// source whose reads can be interrupted by cancellation.
func ReadPublishFrame(ctx context.Context, source io.Reader, destination io.Writer, maxMetadata, maxArchive int64) (PublishFrame, error) {
	if ctx == nil || source == nil || destination == nil || maxMetadata < 1 || maxMetadata > 16<<20 || maxArchive < 1 || maxArchive > 1<<30 {
		return PublishFrame{}, errors.New("Cargo publication framing parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return PublishFrame{}, errors.New("Cargo publication framing requires a deadline")
	}
	reader := &contextReader{ctx: ctx, source: source}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return PublishFrame{}, errors.New("Cargo metadata length is incomplete")
	}
	metadataSize := int64(binary.LittleEndian.Uint32(header[:]))
	if metadataSize < 1 || metadataSize > maxMetadata {
		return PublishFrame{}, errors.New("Cargo metadata exceeds its limit")
	}
	metadata := make([]byte, int(metadataSize))
	if _, err := io.ReadFull(reader, metadata); err != nil {
		return PublishFrame{}, errors.New("Cargo metadata is incomplete")
	}
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return PublishFrame{}, errors.New("Cargo archive length is incomplete")
	}
	archiveSize := int64(binary.LittleEndian.Uint32(header[:]))
	if archiveSize < 1 || archiveSize > maxArchive {
		return PublishFrame{}, errors.New("Cargo archive exceeds its limit")
	}
	hash := sha256.New()
	written, err := io.CopyN(io.MultiWriter(destination, hash), reader, archiveSize)
	if err != nil || written != archiveSize {
		return PublishFrame{}, errors.New("Cargo archive is incomplete or could not be staged")
	}
	var extra [1]byte
	n, err := io.ReadFull(reader, extra[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return PublishFrame{}, errors.New("Cargo publication contains trailing data or could not be completed")
	}
	return PublishFrame{Metadata: metadata, Size: written, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}
