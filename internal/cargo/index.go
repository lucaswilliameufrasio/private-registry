package cargo

import (
	"encoding/hex"
	"encoding/json"
	"errors"
)

type publishDependency struct {
	Name          string   `json:"name"`
	VersionReq    string   `json:"version_req"`
	Features      []string `json:"features"`
	Optional      *bool    `json:"optional"`
	Default       *bool    `json:"default_features"`
	Target        *string  `json:"target"`
	Kind          *string  `json:"kind"`
	Registry      *string  `json:"registry"`
	ExplicitAlias *string  `json:"explicit_name_in_toml"`
}

type indexDependency struct {
	Name     string   `json:"name"`
	Req      string   `json:"req"`
	Features []string `json:"features"`
	Optional bool     `json:"optional"`
	Default  bool     `json:"default_features"`
	Target   *string  `json:"target,omitempty"`
	Kind     string   `json:"kind"`
	Registry *string  `json:"registry,omitempty"`
	Package  *string  `json:"package,omitempty"`
}

// IndexEntry is a partial projection of publish metadata, not authorization
// to serve a version. Catalog uniqueness, semver, dependency semantics, policy,
// archive identity and release approval must be enforced independently.
type IndexEntry struct {
	Name        string              `json:"name"`
	Version     string              `json:"vers"`
	Deps        []indexDependency   `json:"deps"`
	Checksum    string              `json:"cksum"`
	Features    map[string][]string `json:"features"`
	Yanked      bool                `json:"yanked"`
	Links       *string             `json:"links,omitempty"`
	RustVersion *string             `json:"rust_version,omitempty"`
}

// ProjectIndex maps the Cargo publish API's dependency aliases to their index
// representation. Missing optional values use Cargo's index defaults. Unknown
// API fields remain available in the original metadata but are not projected.
func ProjectIndex(data []byte, checksum string) (IndexEntry, error) {
	if err := CheckMetadataJSON(data); err != nil {
		return IndexEntry{}, err
	}
	decoded, err := hex.DecodeString(checksum)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != checksum {
		return IndexEntry{}, errors.New("Cargo archive checksum is invalid")
	}
	var metadata struct {
		Name        string              `json:"name"`
		Version     string              `json:"vers"`
		Deps        []publishDependency `json:"deps"`
		Features    map[string][]string `json:"features"`
		Links       *string             `json:"links"`
		RustVersion *string             `json:"rust_version"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil || metadata.Name == "" || metadata.Version == "" || len(metadata.Name) > 255 || len(metadata.Version) > 255 || len(metadata.Deps) > 10000 || len(metadata.Features) > 10000 {
		return IndexEntry{}, errors.New("Cargo publication metadata fields are invalid")
	}
	if _, err := VersionIdentity(metadata.Version); err != nil {
		return IndexEntry{}, err
	}
	entry := IndexEntry{Name: metadata.Name, Version: metadata.Version, Deps: make([]indexDependency, 0, len(metadata.Deps)), Checksum: checksum, Features: metadata.Features, Links: metadata.Links, RustVersion: metadata.RustVersion}
	if entry.Features == nil {
		entry.Features = make(map[string][]string)
	}
	for name, features := range entry.Features {
		if len(name) > 4096 || features == nil || len(features) > 10000 {
			return IndexEntry{}, errors.New("Cargo feature metadata is invalid")
		}
		for _, feature := range features {
			if len(feature) > 4096 {
				return IndexEntry{}, errors.New("Cargo feature metadata is invalid")
			}
		}
	}
	for _, dependency := range metadata.Deps {
		if dependency.Name == "" || dependency.VersionReq == "" || len(dependency.Name) > 255 || len(dependency.VersionReq) > 4096 || len(dependency.Features) > 10000 {
			return IndexEntry{}, errors.New("Cargo dependency metadata is invalid")
		}
		item := indexDependency{Name: dependency.Name, Req: dependency.VersionReq, Features: dependency.Features, Default: true, Kind: "normal", Target: dependency.Target, Registry: dependency.Registry}
		if item.Features == nil {
			item.Features = []string{}
		}
		for _, feature := range item.Features {
			if len(feature) > 4096 {
				return IndexEntry{}, errors.New("Cargo dependency feature metadata is invalid")
			}
		}
		if dependency.Optional != nil {
			item.Optional = *dependency.Optional
		}
		if dependency.Default != nil {
			item.Default = *dependency.Default
		}
		if dependency.Kind != nil && *dependency.Kind != "" {
			if *dependency.Kind != "normal" && *dependency.Kind != "build" && *dependency.Kind != "dev" {
				return IndexEntry{}, errors.New("Cargo dependency kind is invalid")
			}
			item.Kind = *dependency.Kind
		}
		if dependency.ExplicitAlias != nil {
			if *dependency.ExplicitAlias == "" || len(*dependency.ExplicitAlias) > 255 {
				return IndexEntry{}, errors.New("Cargo dependency alias is invalid")
			}
			original := dependency.Name
			item.Name = *dependency.ExplicitAlias
			item.Package = &original
		}
		entry.Deps = append(entry.Deps, item)
	}
	return entry, nil
}
