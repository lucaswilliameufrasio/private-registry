package gomod

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	modulezip "golang.org/x/mod/zip"
)

// PackedModule describes a locally created archive. The caller owns the output
// file and must discard it on error. The source directory must not change while
// it is being packed; this operation does not infer a VCS revision or time.
type PackedModule struct {
	ModulePath string
	Version    string
	ModBytes   []byte
	ZipSize    int64
	ZipSHA256  string
}

// PackDirectory writes a Go module archive to a caller-owned, empty regular
// file outside the source tree. It applies the same archive validation used by
// the server before returning metadata suitable for an upload reservation.
func PackDirectory(ctx context.Context, source, version string, output *os.File, maxFiles int) (PackedModule, error) {
	if ctx == nil || output == nil || source == "" || maxFiles < 1 || maxFiles > 100000 {
		return PackedModule{}, ErrInvalidPublication
	}
	if _, ok := ctx.Deadline(); !ok {
		return PackedModule{}, ErrInvalidPublication
	}
	root, err := filepath.Abs(source)
	if err != nil {
		return PackedModule{}, ErrInvalidPublication
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return PackedModule{}, ErrInvalidPublication
	}
	outputPath, err := filepath.Abs(output.Name())
	if err != nil {
		return PackedModule{}, ErrInvalidPublication
	}
	outputPath, err = filepath.EvalSymlinks(outputPath)
	if err != nil {
		return PackedModule{}, ErrInvalidPublication
	}
	relative, err := filepath.Rel(root, outputPath)
	if err != nil || relative == "." || (relative != ".." && !isParentRelative(relative)) {
		return PackedModule{}, errors.New("Go archive output must be outside the source directory")
	}
	info, err := output.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		return PackedModule{}, errors.New("Go archive output must be an empty regular file")
	}
	pathInfo, err := os.Stat(outputPath)
	if err != nil || !os.SameFile(info, pathInfo) {
		return PackedModule{}, errors.New("Go archive output path does not identify its file")
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		return PackedModule{}, errors.New("Go archive output could not be rewound")
	}
	modFile, err := os.Open(filepath.Join(root, "go.mod"))
	if err != nil {
		return PackedModule{}, ErrInvalidPublication
	}
	mod, readErr := io.ReadAll(io.LimitReader(modFile, modulezip.MaxGoMod+1))
	closeErr := modFile.Close()
	if readErr != nil || closeErr != nil || len(mod) == 0 || len(mod) > modulezip.MaxGoMod {
		return PackedModule{}, ErrInvalidPublication
	}
	parsed, err := modfile.Parse("go.mod", mod, nil)
	if err != nil || parsed.Module == nil || module.CanonicalVersion(version) != version || module.Check(parsed.Module.Mod.Path, version) != nil {
		return PackedModule{}, ErrInvalidPublication
	}
	writer := &boundedPackWriter{ctx: ctx, writer: output, remaining: modulezip.MaxZipFile}
	if err := modulezip.CreateFromDir(writer, module.Version{Path: parsed.Module.Mod.Path, Version: version}, root); err != nil {
		return PackedModule{}, errors.New("Go module archive could not be created")
	}
	if err := output.Sync(); err != nil {
		return PackedModule{}, errors.New("Go module archive could not be synchronized")
	}
	if err := ValidatePublication(ctx, parsed.Module.Mod.Path, version, mod, outputPath, maxFiles); err != nil {
		return PackedModule{}, err
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		return PackedModule{}, errors.New("Go module archive could not be read")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, &contextReader{ctx: ctx, source: output})
	if err != nil || size < 1 || size > modulezip.MaxZipFile {
		return PackedModule{}, errors.New("Go module archive could not be hashed")
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		return PackedModule{}, errors.New("Go module archive could not be rewound")
	}
	return PackedModule{ModulePath: parsed.Module.Mod.Path, Version: version, ModBytes: mod, ZipSize: size, ZipSHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func isParentRelative(path string) bool {
	return len(path) > 3 && path[:3] == ".."+string(filepath.Separator)
}

type boundedPackWriter struct {
	ctx       context.Context
	writer    io.Writer
	remaining int64
}

func (w *boundedPackWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(data)) > w.remaining {
		return 0, errors.New("Go module archive exceeds size limit")
	}
	n, err := w.writer.Write(data)
	w.remaining -= int64(n)
	return n, err
}
