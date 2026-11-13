package cargo

import (
	"errors"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

// ValidateManifestIdentity confirms that the normalized manifest explicitly
// names the same crate and version as the publication. It does not validate
// dependency semantics, signatures, policy, or the surrounding archive.
func ValidateManifestIdentity(manifest []byte, name, version string) error {
	if len(manifest) == 0 || len(manifest) > 16<<20 || !utf8.Valid(manifest) || !safeCrateName(name) || !safeArchiveIdentity(version) {
		return errors.New("Cargo manifest identity parameters are invalid")
	}
	var parsed struct {
		Package struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(manifest), &parsed); err != nil {
		return errors.New("Cargo manifest is invalid TOML")
	}
	if parsed.Package.Name != name || parsed.Package.Version != version {
		return errors.New("Cargo manifest identity does not match publication")
	}
	return nil
}
