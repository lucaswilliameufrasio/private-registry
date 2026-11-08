package cargo

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/BurntSushi/toml"
)

// ValidateManifestFeatures compares explicit feature definitions in the
// normalized crate manifest with publication metadata. It does not validate
// dependency semantics or infer features implicit in optional dependencies.
func ValidateManifestFeatures(manifest, metadata []byte) error {
	if len(manifest) == 0 || len(manifest) > 16<<20 {
		return errors.New("Cargo manifest size is invalid")
	}
	if err := CheckMetadataJSON(metadata); err != nil {
		return err
	}
	var fromManifest struct {
		Features map[string][]string `toml:"features"`
	}
	if _, err := toml.Decode(string(manifest), &fromManifest); err != nil {
		return errors.New("Cargo manifest features are invalid")
	}
	var fromMetadata struct {
		Features map[string][]string `json:"features"`
	}
	if err := json.Unmarshal(metadata, &fromMetadata); err != nil {
		return errors.New("Cargo publication features are invalid")
	}
	if len(fromManifest.Features) != len(fromMetadata.Features) {
		return errors.New("Cargo manifest features differ from publication metadata")
	}
	for name, declared := range fromManifest.Features {
		published, ok := fromMetadata.Features[name]
		if !ok || declared == nil || published == nil || len(declared) != len(published) {
			return errors.New("Cargo manifest features differ from publication metadata")
		}
		declared = slices.Clone(declared)
		published = slices.Clone(published)
		slices.Sort(declared)
		slices.Sort(published)
		if !slices.Equal(declared, published) {
			return errors.New("Cargo manifest features differ from publication metadata")
		}
	}
	return nil
}
