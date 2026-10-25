//go:build windows

package storage

// Windows does not expose directory fsync through os.File.Sync. File contents
// are still synchronized before finalization; directory-entry durability is
// therefore weaker than on the supported Linux server platform.
func syncDirectory(string) error {
	return nil
}
