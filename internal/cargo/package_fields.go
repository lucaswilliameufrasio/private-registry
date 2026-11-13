package cargo

import (
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

// ValidateManifestIndexFields compares package fields copied to the sparse
// index. It does not establish that a rust-version is a valid Cargo version
// requirement or that links values are unique across the dependency graph.
func ValidateManifestIndexFields(manifest, metadata []byte) error {
	if len(manifest) == 0 || len(manifest) > 16<<20 || !utf8.Valid(manifest) {
		return errors.New("Cargo manifest is invalid")
	}
	if err := CheckMetadataJSON(metadata); err != nil {
		return err
	}
	var document struct {
		Package struct {
			Links       *string `toml:"links"`
			RustVersion *string `toml:"rust-version"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(manifest), &document); err != nil {
		return errors.New("Cargo manifest index fields are invalid")
	}
	var payload struct {
		Links       *string `json:"links"`
		RustVersion *string `json:"rust_version"`
	}
	if err := json.Unmarshal(metadata, &payload); err != nil {
		return errors.New("Cargo publication index fields are invalid")
	}
	if !equalOptionalString(document.Package.Links, payload.Links) || !equalOptionalString(document.Package.RustVersion, payload.RustVersion) {
		return errors.New("Cargo manifest index fields differ from publication metadata")
	}
	return nil
}

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
