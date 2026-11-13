package gomod

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

const maxCentralDirectoryBytes = 16 << 20

// preflightZipDirectory bounds directory allocation before archive/zip opens
// it. Standard single-disk ZIP and ZIP64 directories are accepted within the
// same bounds. Prepended executables and multidisk archives are not accepted.
func preflightZipDirectory(ctx context.Context, path string, size int64, maxFiles int) (retErr error) {
	if ctx == nil {
		return errors.New("Go ZIP directory context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("Go ZIP directory could not be opened")
	}
	defer func() {
		if err := file.Close(); err != nil {
			retErr = errors.Join(retErr, errors.New("Go ZIP directory could not be closed"))
		}
	}()
	if size < 22 {
		return errors.New("Go ZIP end record is invalid")
	}
	tailSize := min(size, int64(22+65535))
	tail := make([]byte, int(tailSize))
	if _, err := file.ReadAt(tail, size-tailSize); err != nil {
		return errors.New("Go ZIP end record could not be read")
	}
	var end int = -1
	for offset := len(tail) - 22; offset >= 0; offset-- {
		if bytes.Equal(tail[offset:offset+4], []byte{'P', 'K', 5, 6}) && offset+22+int(binary.LittleEndian.Uint16(tail[offset+20:offset+22])) == len(tail) {
			end = offset
			break
		}
	}
	if end < 0 {
		return errors.New("Go ZIP end record is invalid")
	}
	record := tail[end : end+22]
	disk := binary.LittleEndian.Uint16(record[4:6])
	directoryDisk := binary.LittleEndian.Uint16(record[6:8])
	diskEntries := binary.LittleEndian.Uint16(record[8:10])
	legacyEntries := binary.LittleEndian.Uint16(record[10:12])
	legacySize := binary.LittleEndian.Uint32(record[12:16])
	legacyOffset := binary.LittleEndian.Uint32(record[16:20])
	endOffset := size - tailSize + int64(end)
	if disk != 0 || directoryDisk != 0 || diskEntries != legacyEntries || maxFiles < 1 {
		return errors.New("Go ZIP directory exceeds limits or uses an unsupported format")
	}
	entries, directorySize, directoryOffset := uint64(legacyEntries), uint64(legacySize), uint64(legacyOffset)
	if legacyEntries == 0xffff || legacySize == 0xffffffff || legacyOffset == 0xffffffff {
		locatorOffset := endOffset - 20
		if locatorOffset < 0 {
			return errors.New("Go ZIP64 locator is invalid")
		}
		var locator [20]byte
		if _, err := file.ReadAt(locator[:], locatorOffset); err != nil || !bytes.Equal(locator[:4], []byte{'P', 'K', 6, 7}) || binary.LittleEndian.Uint32(locator[4:8]) != 0 || binary.LittleEndian.Uint32(locator[16:20]) != 1 {
			return errors.New("Go ZIP64 locator is invalid")
		}
		zip64Offset := binary.LittleEndian.Uint64(locator[8:16])
		if locatorOffset < 56 || zip64Offset > uint64(locatorOffset-56) {
			return errors.New("Go ZIP64 end record is invalid")
		}
		var zip64 [56]byte
		if _, err := file.ReadAt(zip64[:], int64(zip64Offset)); err != nil || !bytes.Equal(zip64[:4], []byte{'P', 'K', 6, 6}) {
			return errors.New("Go ZIP64 end record is invalid")
		}
		recordSize := binary.LittleEndian.Uint64(zip64[4:12])
		if recordSize < 44 || recordSize > 1<<20 || zip64Offset+12+recordSize != uint64(locatorOffset) || binary.LittleEndian.Uint32(zip64[16:20]) != 0 || binary.LittleEndian.Uint32(zip64[20:24]) != 0 || binary.LittleEndian.Uint64(zip64[24:32]) != binary.LittleEndian.Uint64(zip64[32:40]) {
			return errors.New("Go ZIP64 end record is invalid")
		}
		entries = binary.LittleEndian.Uint64(zip64[32:40])
		directorySize = binary.LittleEndian.Uint64(zip64[40:48])
		directoryOffset = binary.LittleEndian.Uint64(zip64[48:56])
		if (legacyEntries != 0xffff && uint64(legacyEntries) != entries) || (legacySize != 0xffffffff && uint64(legacySize) != directorySize) || (legacyOffset != 0xffffffff && uint64(legacyOffset) != directoryOffset) {
			return errors.New("Go ZIP64 end records disagree")
		}
		endOffset = int64(zip64Offset)
	}
	if entries == 0 || entries > uint64(maxFiles) || directorySize > maxCentralDirectoryBytes || directoryOffset > uint64(endOffset) || directorySize != uint64(endOffset)-directoryOffset {
		return errors.New("Go ZIP directory exceeds limits or uses an unsupported format")
	}
	position := int64(directoryOffset)
	var header [46]byte
	for index := 0; index < int(entries); index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if position+int64(len(header)) > endOffset {
			return errors.New("Go ZIP directory entry is truncated")
		}
		if _, err := file.ReadAt(header[:], position); err != nil && !errors.Is(err, io.EOF) {
			return errors.New("Go ZIP directory entry could not be read")
		}
		if !bytes.Equal(header[:4], []byte{'P', 'K', 1, 2}) {
			return errors.New("Go ZIP directory entry is invalid")
		}
		name := int64(binary.LittleEndian.Uint16(header[28:30]))
		extra := int64(binary.LittleEndian.Uint16(header[30:32]))
		comment := int64(binary.LittleEndian.Uint16(header[32:34]))
		position += int64(len(header)) + name + extra + comment
		if position > endOffset {
			return errors.New("Go ZIP directory entry exceeds its boundary")
		}
	}
	if position != endOffset {
		return errors.New("Go ZIP directory entry count is inconsistent")
	}
	return nil
}
