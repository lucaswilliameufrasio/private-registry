package cargo

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
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
	MaxFiles             int
	MaxManifestBytes     int64
}

// ArchiveContents is structural evidence only. Manifest must be parsed and its
// package identity and metadata checked independently before any publication.
type ArchiveContents struct {
	Manifest []byte
	Files    int
}

// InspectArchive scans a single gzip-compressed tar without extracting it.
// The source is a caller-owned, exclusively controlled archive; the caller
// must separately authenticate bytes and bound disk, CPU and read latency.
func InspectArchive(ctx context.Context, source io.Reader, name, version string, limits ArchiveLimits) (ArchiveContents, error) {
	if ctx == nil || source == nil || !safeCrateName(name) || !safeArchiveIdentity(version) || limits.MaxCompressedBytes < 1 || limits.MaxCompressedBytes > 1<<30 || limits.MaxUncompressedBytes < 1 || limits.MaxUncompressedBytes > 1<<30 || limits.MaxFiles < 1 || limits.MaxFiles > 100000 || limits.MaxManifestBytes < 1 || limits.MaxManifestBytes > 16<<20 {
		return ArchiveContents{}, errors.New("Cargo archive inspection parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return ArchiveContents{}, errors.New("Cargo archive inspection requires a deadline")
	}
	limited := &io.LimitedReader{R: &contextReader{ctx: ctx, source: source}, N: limits.MaxCompressedBytes + 1}
	buffered := bufio.NewReader(limited)
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return ArchiveContents{}, errors.New("Cargo archive gzip header is invalid")
	}
	defer compressed.Close()
	compressed.Multistream(false)
	uncompressed := &io.LimitedReader{R: compressed, N: limits.MaxUncompressedBytes + 1}
	tarReader := tar.NewReader(uncompressed)
	root := name + "-" + version + "/"
	seen := make(map[string]byte)
	parents := make(map[string]struct{})
	var result ArchiveContents
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ArchiveContents{}, errors.New("Cargo archive tar entry is invalid")
		}
		result.Files++
		if result.Files > limits.MaxFiles || !validArchivePath(header.Name, root) || header.Size < 0 {
			return ArchiveContents{}, errors.New("Cargo archive entry exceeds limits or has an invalid path")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
			return ArchiveContents{}, errors.New("Cargo archive entry type is unsupported")
		}
		canonical := strings.ToLower(strings.TrimSuffix(header.Name, "/"))
		if _, exists := seen[canonical]; exists {
			return ArchiveContents{}, errors.New("Cargo archive contains duplicate paths")
		}
		if header.Typeflag != tar.TypeDir {
			if _, exists := parents[canonical]; exists {
				return ArchiveContents{}, errors.New("Cargo archive file conflicts with a directory")
			}
		}
		for parent := path.Dir(canonical); parent != "." && parent != "/"; parent = path.Dir(parent) {
			if kind, exists := seen[parent]; exists && kind != tar.TypeDir {
				return ArchiveContents{}, errors.New("Cargo archive file conflicts with a directory")
			}
			parents[parent] = struct{}{}
		}
		seen[canonical] = header.Typeflag
		if header.Name == root+"Cargo.toml" {
			if header.Typeflag == tar.TypeDir || header.Size < 1 || header.Size > limits.MaxManifestBytes {
				return ArchiveContents{}, errors.New("Cargo archive manifest exceeds its limit")
			}
			result.Manifest, err = io.ReadAll(io.LimitReader(tarReader, limits.MaxManifestBytes+1))
			if err != nil || int64(len(result.Manifest)) != header.Size {
				return ArchiveContents{}, errors.New("Cargo archive manifest could not be read")
			}
		} else if _, err := io.Copy(io.Discard, tarReader); err != nil {
			return ArchiveContents{}, errors.New("Cargo archive entry could not be read")
		}
	}
	if len(result.Manifest) == 0 {
		return ArchiveContents{}, errors.New("Cargo archive manifest is missing")
	}
	var suffix [4096]byte
	for {
		n, err := uncompressed.Read(suffix[:])
		for _, b := range suffix[:n] {
			if b != 0 {
				return ArchiveContents{}, errors.New("Cargo archive contains data after the tar end marker")
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ArchiveContents{}, errors.New("Cargo archive has an invalid checksum or could not be read")
		}
	}
	if uncompressed.N == 0 {
		return ArchiveContents{}, errors.New("Cargo archive exceeds its uncompressed limit or has an invalid checksum")
	}
	if _, err := buffered.ReadByte(); !errors.Is(err, io.EOF) || limited.N == 0 {
		return ArchiveContents{}, errors.New("Cargo archive exceeds its compressed limit or contains trailing bytes")
	}
	if err := compressed.Close(); err != nil {
		return ArchiveContents{}, errors.New("Cargo archive could not be closed")
	}
	return result, nil
}

func safeArchiveIdentity(value string) bool {
	if value == "" || len(value) > 255 || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' && r != '.' && r != '+' {
			return false
		}
	}
	return true
}

func validArchivePath(name, root string) bool {
	if len(name) > 4096 || !utf8.ValidString(name) || !strings.HasPrefix(name, root) || len(name) == len(root) || strings.ContainsAny(name, "\\:") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	clean := path.Clean(name)
	return clean == strings.TrimSuffix(name, "/") && !bytes.Contains([]byte(name), []byte("//"))
}
