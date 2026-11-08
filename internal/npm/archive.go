package npm

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
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
	Manifest json.RawMessage
	Entries  int
}

// InspectArchive scans one gzip/tar without extracting it. The caller owns the
// source, must prevent it changing and must bound aggregate CPU and I/O. A
// context deadline cannot interrupt a reader that ignores cancellation.
func InspectArchive(ctx context.Context, source io.Reader, name, version string, limits ArchiveLimits) (ArchiveContents, error) {
	if ctx == nil || source == nil || name == "" || version == "" || len(name) > 255 || len(version) > 255 || limits.MaxCompressedBytes < 1 || limits.MaxCompressedBytes > 64<<20 || limits.MaxUncompressedBytes < 1 || limits.MaxUncompressedBytes > 1<<30 || limits.MaxEntries < 1 || limits.MaxEntries > 100000 || limits.MaxManifestBytes < 1 || limits.MaxManifestBytes > 16<<20 {
		return ArchiveContents{}, errors.New("npm archive parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return ArchiveContents{}, errors.New("npm archive inspection requires a deadline")
	}
	compressedLimit := &io.LimitedReader{R: &contextReader{ctx: ctx, source: source}, N: limits.MaxCompressedBytes + 1}
	buffered := bufio.NewReader(compressedLimit)
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return ArchiveContents{}, errors.New("npm archive gzip header is invalid")
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
			return ArchiveContents{}, errors.New("npm archive tar entry is invalid")
		}
		result.Entries++
		if result.Entries > limits.MaxEntries || !validArchivePath(header.Name) || header.Size < 0 {
			return ArchiveContents{}, errors.New("npm archive entry has an invalid path or exceeds its limit")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
			return ArchiveContents{}, errors.New("npm archive entry type is unsupported")
		}
		canonical := strings.ToLower(strings.TrimSuffix(header.Name, "/"))
		if _, exists := seen[canonical]; exists {
			return ArchiveContents{}, errors.New("npm archive contains duplicate paths")
		}
		if header.Typeflag != tar.TypeDir {
			if _, exists := parents[canonical]; exists {
				return ArchiveContents{}, errors.New("npm archive file conflicts with a directory")
			}
		}
		for parent := path.Dir(canonical); parent != "." && parent != "/"; parent = path.Dir(parent) {
			if kind, exists := seen[parent]; exists && kind != tar.TypeDir {
				return ArchiveContents{}, errors.New("npm archive file conflicts with a directory")
			}
			parents[parent] = struct{}{}
		}
		seen[canonical] = header.Typeflag
		if header.Name == "package/package.json" {
			if header.Typeflag == tar.TypeDir || header.Size < 1 || header.Size > limits.MaxManifestBytes {
				return ArchiveContents{}, errors.New("npm archive manifest exceeds its limit")
			}
			result.Manifest, err = io.ReadAll(io.LimitReader(tarReader, limits.MaxManifestBytes+1))
			if err != nil || int64(len(result.Manifest)) != header.Size {
				return ArchiveContents{}, errors.New("npm archive manifest could not be read")
			}
		} else if _, err := io.Copy(io.Discard, tarReader); err != nil {
			return ArchiveContents{}, errors.New("npm archive entry could not be read")
		}
	}
	if len(result.Manifest) == 0 || !utf8.Valid(result.Manifest) || checkJSONSyntax(result.Manifest) != nil {
		return ArchiveContents{}, errors.New("npm archive manifest is missing or invalid")
	}
	var identity struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(result.Manifest, &fields) != nil || exactFields(fields, []string{"name", "version"}) != nil || json.Unmarshal(result.Manifest, &identity) != nil || identity.Name != name || !compatibleArchiveVersion(version, identity.Version) {
		return ArchiveContents{}, errors.New("npm archive manifest identity does not match")
	}
	var suffix [4096]byte
	for {
		n, err := uncompressed.Read(suffix[:])
		for _, value := range suffix[:n] {
			if value != 0 {
				return ArchiveContents{}, errors.New("npm archive contains data after the tar end marker")
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ArchiveContents{}, errors.New("npm archive checksum or data is invalid")
		}
	}
	if uncompressed.N == 0 {
		return ArchiveContents{}, errors.New("npm archive exceeds its uncompressed limit")
	}
	if _, err := buffered.ReadByte(); !errors.Is(err, io.EOF) || compressedLimit.N == 0 {
		return ArchiveContents{}, errors.New("npm archive exceeds its compressed limit or contains trailing bytes")
	}
	if err := compressed.Close(); err != nil {
		return ArchiveContents{}, errors.New("npm archive could not be closed")
	}
	return result, nil
}

func validArchivePath(name string) bool {
	if len(name) > 4096 || !utf8.ValidString(name) || !strings.HasPrefix(name, "package/") || strings.ContainsAny(name, "\\:") || strings.Contains(name, "//") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return path.Clean(name) == strings.TrimSuffix(name, "/")
}
