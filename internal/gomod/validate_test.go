package gomod

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type zipEntry struct {
	name string
	data string
	mode os.FileMode
}

func TestZipDirectoryPreflightRejectsForgedCountsAndZIP64(t *testing.T) {
	path := writeArchive(t, []zipEntry{{name: "example.com/m@v1.0.0/a", data: "a"}, {name: "example.com/m@v1.0.0/b", data: "b"}})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightZipDirectory(context.Background(), path, int64(len(data)), 2); err != nil {
		t.Fatal("valid directory rejected:", err)
	}
	if err := preflightZipDirectory(context.Background(), path, int64(len(data)), 1); err == nil {
		t.Fatal("directory exceeding entry limit accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := preflightZipDirectory(canceled, path, int64(len(data)), 2); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled directory preflight = %v", err)
	}
	end := bytes.LastIndex(data, []byte{'P', 'K', 5, 6})
	if end < 0 || end+22 != len(data) {
		t.Fatal("fixture end record is invalid")
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"forged entry count", func(b []byte) {
			binary.LittleEndian.PutUint16(b[end+8:end+10], 1)
			binary.LittleEndian.PutUint16(b[end+10:end+12], 1)
		}},
		{"zip64", func(b []byte) {
			binary.LittleEndian.PutUint16(b[end+8:end+10], 0xffff)
			binary.LittleEndian.PutUint16(b[end+10:end+12], 0xffff)
		}},
		{"oversized directory", func(b []byte) { binary.LittleEndian.PutUint32(b[end+12:end+16], maxCentralDirectoryBytes+1) }},
		{"multi disk", func(b []byte) { binary.LittleEndian.PutUint16(b[end+4:end+6], 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := bytes.Clone(data)
			tc.mutate(modified)
			candidate := filepath.Join(t.TempDir(), "forged.zip")
			if err := os.WriteFile(candidate, modified, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := preflightZipDirectory(context.Background(), candidate, int64(len(modified)), 10); err == nil {
				t.Fatal("invalid ZIP directory was accepted")
			}
		})
	}
}

func TestValidatePublicationWithBoundedZIP64Directory(t *testing.T) {
	modulePath, version := "example.com/private/zip64", "v1.0.0"
	mod := []byte("module " + modulePath + "\n\ngo 1.24\n")
	path := writeArchive(t, []zipEntry{{name: modulePath + "@" + version + "/go.mod", data: string(mod)}, {name: modulePath + "@" + version + "/module.go", data: "package zip64\n"}})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	end := bytes.LastIndex(data, []byte{'P', 'K', 5, 6})
	if end < 0 || end+22 != len(data) {
		t.Fatal("fixture end record is invalid")
	}
	legacy := bytes.Clone(data[end:])
	entries := binary.LittleEndian.Uint16(legacy[10:12])
	directorySize := binary.LittleEndian.Uint32(legacy[12:16])
	directoryOffset := binary.LittleEndian.Uint32(legacy[16:20])
	zip64 := make([]byte, 56)
	copy(zip64[:4], []byte{'P', 'K', 6, 6})
	binary.LittleEndian.PutUint64(zip64[4:12], 44)
	binary.LittleEndian.PutUint16(zip64[12:14], 45)
	binary.LittleEndian.PutUint16(zip64[14:16], 45)
	binary.LittleEndian.PutUint64(zip64[24:32], uint64(entries))
	binary.LittleEndian.PutUint64(zip64[32:40], uint64(entries))
	binary.LittleEndian.PutUint64(zip64[40:48], uint64(directorySize))
	binary.LittleEndian.PutUint64(zip64[48:56], uint64(directoryOffset))
	locator := make([]byte, 20)
	copy(locator[:4], []byte{'P', 'K', 6, 7})
	binary.LittleEndian.PutUint64(locator[8:16], uint64(end))
	binary.LittleEndian.PutUint32(locator[16:20], 1)
	binary.LittleEndian.PutUint16(legacy[8:10], 0xffff)
	binary.LittleEndian.PutUint16(legacy[10:12], 0xffff)
	binary.LittleEndian.PutUint32(legacy[12:16], 0xffffffff)
	binary.LittleEndian.PutUint32(legacy[16:20], 0xffffffff)
	converted := append(bytes.Clone(data[:end]), zip64...)
	converted = append(converted, locator...)
	converted = append(converted, legacy...)
	zip64Path := filepath.Join(t.TempDir(), "zip64.zip")
	if err := os.WriteFile(zip64Path, converted, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ValidatePublication(ctx, modulePath, version, mod, zip64Path, 10); err != nil {
		t.Fatalf("bounded valid ZIP64 rejected: %v", err)
	}
	if err := preflightZipDirectory(ctx, zip64Path, int64(len(converted)), 1); err == nil {
		t.Fatal("ZIP64 directory exceeding entry limit was accepted")
	}
	zip64End := end
	locatorStart := zip64End + len(zip64)
	legacyStart := locatorStart + len(locator)
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"forged ZIP64 count", func(b []byte) {
			binary.LittleEndian.PutUint64(b[zip64End+24:zip64End+32], 1)
			binary.LittleEndian.PutUint64(b[zip64End+32:zip64End+40], 1)
		}},
		{"oversized ZIP64 record", func(b []byte) { binary.LittleEndian.PutUint64(b[zip64End+4:zip64End+12], 1<<20+1) }},
		{"ZIP64 multidisk", func(b []byte) { binary.LittleEndian.PutUint32(b[zip64End+16:zip64End+20], 1) }},
		{"invalid ZIP64 locator", func(b []byte) { binary.LittleEndian.PutUint64(b[locatorStart+8:locatorStart+16], uint64(len(b))) }},
		{"inconsistent legacy size", func(b []byte) { binary.LittleEndian.PutUint32(b[legacyStart+12:legacyStart+16], directorySize+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := bytes.Clone(converted)
			tc.mutate(modified)
			candidate := filepath.Join(t.TempDir(), "invalid-zip64.zip")
			if err := os.WriteFile(candidate, modified, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := preflightZipDirectory(ctx, candidate, int64(len(modified)), 10); err == nil {
				t.Fatal("malformed ZIP64 directory was accepted")
			}
		})
	}
}

func writeArchive(t *testing.T, entries []zipEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "module.zip")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(file)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		}
		out, err := w.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := out.Write([]byte(entry.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidatePublicationGoModule(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	modulePath, version := "example.com/private/parent/v2", "v2.1.0"
	mod := []byte("module example.com/private/parent/v2\n\ngo 1.24\n")
	prefix := modulePath + "@" + version + "/"
	valid := []zipEntry{{name: prefix + "go.mod", data: string(mod)}, {name: prefix + "parent.go", data: "package parent\n"}}
	path := writeArchive(t, valid)
	if err := ValidatePublication(ctx, modulePath, version, mod, path, 10); err != nil {
		t.Fatal("valid module rejected:", err)
	}
	pseudo := "v2.0.1-0.20260102150405-0123456789ab"
	pseudoArchive := writeArchive(t, []zipEntry{{name: modulePath + "@" + pseudo + "/go.mod", data: string(mod)}})
	if err := ValidatePublication(ctx, modulePath, pseudo, mod, pseudoArchive, 10); err != nil {
		t.Fatal("valid pseudo-version rejected:", err)
	}
	for _, tc := range []struct {
		name    string
		module  string
		version string
		mod     []byte
		entries []zipEntry
		limit   int
	}{
		{"wrong major", modulePath, "v1.0.0", mod, valid, 10},
		{"noncanonical version", modulePath, "v2.1", mod, valid, 10},
		{"mismatched module", modulePath, version, []byte("module example.com/other\n"), valid, 10},
		{"different go.mod", modulePath, version, []byte("module example.com/private/parent/v2\n\ngo 1.23\n"), valid, 10},
		{"traversal", modulePath, version, mod, []zipEntry{{name: prefix + "../escape", data: "bad"}}, 10},
		{"case collision", modulePath, version, mod, []zipEntry{{name: prefix + "A.go", data: "package p"}, {name: prefix + "a.go", data: "package p"}}, 10},
		{"duplicate file", modulePath, version, mod, []zipEntry{{name: prefix + "a.go", data: "package p"}, {name: prefix + "a.go", data: "package p"}}, 10},
		{"symlink", modulePath, version, mod, []zipEntry{{name: prefix + "link", data: "../outside", mode: os.ModeSymlink | 0o777}}, 10},
		{"file count", modulePath, version, mod, valid, 1},
		{"empty archive", modulePath, version, mod, nil, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := writeArchive(t, tc.entries)
			if err := ValidatePublication(ctx, tc.module, tc.version, tc.mod, archive, tc.limit); err == nil {
				t.Fatal("invalid publication was accepted")
			}
		})
	}
	if err := ValidatePublication(context.Background(), modulePath, version, mod, path, 10); err == nil {
		t.Fatal("validation without deadline was accepted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if err := ValidatePublication(canceled, modulePath, version, mod, path, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled validation = %v", err)
	}
	archiveBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	position := bytes.Index(archiveBytes, []byte("package parent"))
	if position < 0 {
		t.Fatal("fixture content not found")
	}
	archiveBytes[position] ^= 1
	corrupt := filepath.Join(t.TempDir(), "corrupt.zip")
	if err := os.WriteFile(corrupt, archiveBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublication(ctx, modulePath, version, mod, corrupt, 10); err == nil {
		t.Fatal("archive with corrupted file bytes was accepted")
	}
}
