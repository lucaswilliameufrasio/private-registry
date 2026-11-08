package pub

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

type ArchiveLimits struct {
	MaxCompressedBytes   int64
	MaxUncompressedBytes int64
	MaxEntries           int
	MaxManifestBytes     int64
}

// ArchiveContents contains only structural evidence, not authorization or
// proof that the package is safe to execute or matches the publish metadata.
type ArchiveContents struct {
	Manifest []byte
	Entries  int
	SHA256   string
	Size     int64
}

// InspectPackage validates both the archive structure and its manifest's
// exact identity. It does not authorize or publish the package.
func InspectPackage(ctx context.Context, source io.Reader, name, version string, limits ArchiveLimits) (ArchiveContents, error) {
	if source == nil || ValidateName(name) != nil {
		return ArchiveContents{}, errors.New("Pub package name is invalid")
	}
	if _, err := VersionIdentity(version); err != nil {
		return ArchiveContents{}, err
	}
	digest := sha256.New()
	counter := &countingWriter{writer: digest}
	contents, err := InspectArchive(ctx, io.TeeReader(source, counter), limits)
	if err != nil {
		return ArchiveContents{}, err
	}
	if err := ValidatePubspec(contents.Manifest, name, version); err != nil {
		return ArchiveContents{}, err
	}
	contents.SHA256 = hex.EncodeToString(digest.Sum(nil))
	contents.Size = counter.size
	return contents, nil
}

type countingWriter struct {
	writer io.Writer
	size   int64
}

func (w *countingWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	w.size += int64(n)
	return n, err
}

// InspectArchive scans one gzip/tar without extracting it. The caller owns the
// source, must prevent it changing and must bound aggregate CPU and I/O. A
// context deadline cannot interrupt a reader that ignores cancellation.
func InspectArchive(ctx context.Context, source io.Reader, limits ArchiveLimits) (ArchiveContents, error) {
	if ctx == nil || source == nil || limits.MaxCompressedBytes < 1 || limits.MaxCompressedBytes > 64<<20 || limits.MaxUncompressedBytes < 1 || limits.MaxUncompressedBytes > 1<<30 || limits.MaxEntries < 1 || limits.MaxEntries > 100000 || limits.MaxManifestBytes < 1 || limits.MaxManifestBytes > 16<<20 {
		return ArchiveContents{}, errors.New("Pub archive parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return ArchiveContents{}, errors.New("Pub archive inspection requires a deadline")
	}
	compressedLimit := &io.LimitedReader{R: &contextReader{ctx: ctx, source: source}, N: limits.MaxCompressedBytes + 1}
	buffered := bufio.NewReader(compressedLimit)
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return ArchiveContents{}, errors.New("Pub archive gzip header is invalid")
	}
	defer compressed.Close()
	compressed.Multistream(false)
	uncompressed := &io.LimitedReader{R: compressed, N: limits.MaxUncompressedBytes + 1}
	tarReader := tar.NewReader(uncompressed)
	seen := make(map[string]byte)
	parents := make(map[string]struct{})
	var result ArchiveContents
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ArchiveContents{}, errors.New("Pub archive tar entry is invalid")
		}
		result.Entries++
		if result.Entries > limits.MaxEntries || !validArchivePath(header.Name) || header.Size < 0 {
			return ArchiveContents{}, errors.New("Pub archive entry has an invalid path or exceeds its limit")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
			return ArchiveContents{}, errors.New("Pub archive entry type is unsupported")
		}
		canonical := strings.ToLower(strings.TrimSuffix(header.Name, "/"))
		if _, exists := seen[canonical]; exists {
			return ArchiveContents{}, errors.New("Pub archive contains duplicate paths")
		}
		if header.Typeflag != tar.TypeDir {
			if _, exists := parents[canonical]; exists {
				return ArchiveContents{}, errors.New("Pub archive file conflicts with a directory")
			}
		}
		for parent := path.Dir(canonical); parent != "." && parent != "/"; parent = path.Dir(parent) {
			if kind, exists := seen[parent]; exists && kind != tar.TypeDir {
				return ArchiveContents{}, errors.New("Pub archive file conflicts with a directory")
			}
			parents[parent] = struct{}{}
		}
		seen[canonical] = header.Typeflag
		if header.Name == "pubspec.yaml" {
			if header.Typeflag == tar.TypeDir || header.Size < 1 || header.Size > limits.MaxManifestBytes {
				return ArchiveContents{}, errors.New("Pub archive manifest exceeds its limit")
			}
			result.Manifest, err = io.ReadAll(io.LimitReader(tarReader, limits.MaxManifestBytes+1))
			if err != nil || int64(len(result.Manifest)) != header.Size {
				return ArchiveContents{}, errors.New("Pub archive manifest could not be read")
			}
		} else if _, err := io.Copy(io.Discard, tarReader); err != nil {
			return ArchiveContents{}, errors.New("Pub archive entry could not be read")
		}
	}
	if len(result.Manifest) == 0 || !utf8.Valid(result.Manifest) {
		return ArchiveContents{}, errors.New("Pub archive manifest is missing or invalid UTF-8")
	}
	var suffix [4096]byte
	for {
		n, err := uncompressed.Read(suffix[:])
		for _, value := range suffix[:n] {
			if value != 0 {
				return ArchiveContents{}, errors.New("Pub archive contains data after the tar end marker")
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ArchiveContents{}, errors.New("Pub archive checksum or data is invalid")
		}
	}
	if uncompressed.N == 0 {
		return ArchiveContents{}, errors.New("Pub archive exceeds its uncompressed limit")
	}
	if _, err := buffered.ReadByte(); !errors.Is(err, io.EOF) || compressedLimit.N == 0 {
		return ArchiveContents{}, errors.New("Pub archive exceeds its compressed limit or contains trailing bytes")
	}
	if err := compressed.Close(); err != nil {
		return ArchiveContents{}, errors.New("Pub archive could not be closed")
	}
	return result, nil
}

func validArchivePath(name string) bool {
	if len(name) == 0 || strings.HasPrefix(name, "/") || len(name) > 4096 || !utf8.ValidString(name) || strings.ContainsAny(name, "\\:") || strings.Contains(name, "//") {
		return false
	}
	for _, part := range strings.Split(strings.TrimSuffix(name, "/"), "/") {
		if part == "." || part == ".." || part == "" {
			return false
		}
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return path.Clean(name) == strings.TrimSuffix(name, "/")
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
