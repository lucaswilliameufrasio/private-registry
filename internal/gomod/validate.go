// Package gomod implements Go module protocol boundaries; validation alone
// does not publish a package or grant access to a repository.
package gomod

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	modulezip "golang.org/x/mod/zip"
)

// ValidatePublication verifies a complete Go module upload in caller-owned,
// private and exclusive staging. modBytes are the separately served .mod
// bytes; the archive path must not change during validation. The caller must
// enforce independent disk, CPU and I/O budgets, and must not publish on error.
// This does not authenticate the publisher, commit a version, or contact VCS.
func ValidatePublication(ctx context.Context, modulePath, version string, modBytes []byte, archivePath string, maxFiles int) (retErr error) {
	if ctx == nil || archivePath == "" || len(modBytes) == 0 || len(modBytes) > modulezip.MaxGoMod || maxFiles < 1 || maxFiles > 100000 {
		return errors.New("Go module publication parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("Go module validation requires a deadline")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if module.CanonicalVersion(version) != version || module.Check(modulePath, version) != nil {
		return errors.New("Go module path or version is invalid")
	}
	if module.IsPseudoVersion(version) {
		if _, err := module.PseudoVersionTime(version); err != nil {
			return errors.New("Go pseudo-version is invalid")
		}
	}
	parsed, err := modfile.Parse("go.mod", modBytes, nil)
	if err != nil || parsed.Module == nil || parsed.Module.Mod.Path != modulePath {
		return errors.New("Go module declaration is invalid or does not match")
	}
	info, err := os.Lstat(archivePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > modulezip.MaxZipFile {
		return errors.New("Go module archive is invalid")
	}
	if err := preflightZipDirectory(ctx, archivePath, info.Size(), maxFiles); err != nil {
		return err
	}
	if _, err := modulezip.CheckZip(module.Version{Path: modulePath, Version: version}, archivePath); err != nil {
		return errors.New("Go module archive layout is invalid")
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return errors.New("Go module archive could not be opened")
	}
	defer func() {
		if err := archive.Close(); err != nil {
			retErr = errors.Join(retErr, errors.New("Go module archive could not be closed"))
		}
	}()
	reader, err := zip.NewReader(archive, info.Size())
	if err != nil || len(reader.File) > maxFiles {
		return errors.New("Go module archive file count is invalid")
	}
	prefix := modulePath + "@" + version + "/"
	buffer := make([]byte, 32*1024)
	var total int64
	files := 0
	for _, file := range reader.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		if file.FileInfo().IsDir() {
			continue
		}
		if !file.Mode().IsRegular() || !strings.HasPrefix(file.Name, prefix) {
			return errors.New("Go module archive contains an unsafe file")
		}
		files++
		entry, err := file.Open()
		if err != nil {
			return errors.New("Go module archive entry could not be opened")
		}
		var modContent bytes.Buffer
		destination := io.Writer(io.Discard)
		if file.Name == prefix+"go.mod" {
			destination = &modContent
		}
		entrySize := int64(file.UncompressedSize64)
		if entrySize < 0 || entrySize > modulezip.MaxZipFile-total {
			_ = entry.Close()
			return errors.New("Go module archive entry exceeds the size limit")
		}
		limited := &io.LimitedReader{R: entry, N: entrySize + 1}
		var copied int64
		var readErr error
		for {
			if err := ctx.Err(); err != nil {
				readErr = err
				break
			}
			n, err := limited.Read(buffer)
			if n > 0 {
				copied += int64(n)
				if _, writeErr := destination.Write(buffer[:n]); writeErr != nil {
					readErr = writeErr
					break
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil || n == 0 {
				readErr = errors.New("archive entry could not be read")
				break
			}
		}
		closeErr := entry.Close()
		if err := ctx.Err(); err != nil {
			return err
		}
		if readErr != nil || closeErr != nil || limited.N <= 0 || copied != int64(file.UncompressedSize64) {
			return errors.New("Go module archive entry failed integrity verification")
		}
		total += copied
		if file.Name == prefix+"go.mod" && !bytes.Equal(modContent.Bytes(), modBytes) {
			return errors.New("Go module archive declaration does not match the supplied go.mod")
		}
	}
	if files == 0 {
		return errors.New("Go module archive contains no files")
	}
	return ctx.Err()
}
