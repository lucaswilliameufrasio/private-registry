package cargo

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"golang.org/x/mod/semver"
)

type dependencyIdentity struct {
	Alias   string
	Package string
	Kind    string
	Target  string
}

type manifestDependency struct {
	Requirement string
	Features    []string
	Optional    bool
	Default     bool
	Registry    string
}

// ValidateManifestDependencyIdentities verifies that the normalized manifest
// and publish metadata contain the same dependency identities, scopes, flags,
// features and compatible textual requirements. It does not compare registry
// URLs or fully normalize semantically equivalent requirements and is not
// sufficient for publication.
func ValidateManifestDependencyIdentities(manifest, metadata []byte) error {
	return validateManifestDependencies(manifest, metadata, "", "", false)
}

// ValidateManifestDependencies additionally compares dependency registry origins
// using caller-supplied current and default index identities. It does not
// authorize those origins or compare all semantically equivalent requirements.
func ValidateManifestDependencies(manifest, metadata []byte, currentIndex, defaultIndex string) error {
	if currentIndex == "" || defaultIndex == "" || len(currentIndex) > 4096 || len(defaultIndex) > 4096 {
		return errors.New("Cargo registry context is invalid")
	}
	return validateManifestDependencies(manifest, metadata, currentIndex, defaultIndex, true)
}

func validateManifestDependencies(manifest, metadata []byte, currentIndex, defaultIndex string, checkRegistry bool) error {
	if len(manifest) == 0 || len(manifest) > 16<<20 || !utf8.Valid(manifest) {
		return errors.New("Cargo manifest is invalid")
	}
	if err := CheckMetadataJSON(metadata); err != nil {
		return err
	}
	var document map[string]any
	if _, err := toml.Decode(string(manifest), &document); err != nil {
		return errors.New("Cargo manifest is invalid TOML")
	}
	var payload struct {
		Deps []publishDependency `json:"deps"`
	}
	if err := json.Unmarshal(metadata, &payload); err != nil || len(payload.Deps) > 10000 {
		return errors.New("Cargo dependency metadata is invalid")
	}
	expected := make(map[dependencyIdentity]manifestDependency)
	collect := func(table map[string]any, key, kind, target string) error {
		value, found := table[key]
		if !found {
			return nil
		}
		dependencies, ok := value.(map[string]any)
		if !ok || len(dependencies) > 10000 {
			return errors.New("Cargo manifest dependency table is invalid")
		}
		for alias, value := range dependencies {
			packageName := alias
			fields := manifestDependency{Default: true, Features: []string{}, Registry: defaultIndex}
			switch item := value.(type) {
			case string:
				if item == "" {
					return errors.New("Cargo manifest dependency is invalid")
				}
				fields.Requirement = item
			case map[string]any:
				if checkRegistry {
					for _, unsupported := range []string{"registry", "git", "path", "branch", "tag", "rev"} {
						if _, found := item[unsupported]; found {
							return errors.New("Cargo normalized dependency source is unsupported")
						}
					}
					if raw, found := item["registry-index"]; found {
						index, ok := raw.(string)
						if !ok || index == "" || len(index) > 4096 {
							return errors.New("Cargo manifest dependency registry is invalid")
						}
						fields.Registry = index
					}
				}
				if raw, found := item["package"]; found {
					var ok bool
					packageName, ok = raw.(string)
					if !ok || packageName == "" {
						return errors.New("Cargo manifest dependency package is invalid")
					}
				}
				var ok bool
				fields.Requirement, ok = item["version"].(string)
				if !ok || fields.Requirement == "" {
					return errors.New("Cargo manifest dependency version is invalid")
				}
				if raw, found := item["optional"]; found {
					fields.Optional, ok = raw.(bool)
					if !ok {
						return errors.New("Cargo manifest dependency optional flag is invalid")
					}
				}
				if raw, found := item["default-features"]; found {
					fields.Default, ok = raw.(bool)
					if !ok {
						return errors.New("Cargo manifest dependency default features flag is invalid")
					}
				}
				if _, found := item["default_features"]; found {
					return errors.New("Cargo manifest uses an unsupported dependency field")
				}
				if raw, found := item["features"]; found {
					values, ok := raw.([]any)
					if !ok || len(values) > 10000 {
						return errors.New("Cargo manifest dependency features are invalid")
					}
					for _, value := range values {
						feature, ok := value.(string)
						if !ok || len(feature) > 4096 {
							return errors.New("Cargo manifest dependency feature is invalid")
						}
						fields.Features = append(fields.Features, feature)
					}
				}
			default:
				return errors.New("Cargo manifest dependency is invalid")
			}
			if alias == "" || len(alias) > 255 || len(packageName) > 255 || len(target) > 4096 || len(expected) >= 10000 {
				return errors.New("Cargo manifest dependency identity is invalid")
			}
			expected[dependencyIdentity{Alias: alias, Package: packageName, Kind: kind, Target: target}] = fields
		}
		return nil
	}
	collectTables := func(table map[string]any, target string) error {
		for _, item := range []struct{ key, kind string }{{"dependencies", "normal"}, {"dev-dependencies", "dev"}, {"build-dependencies", "build"}} {
			if err := collect(table, item.key, item.kind, target); err != nil {
				return err
			}
		}
		return nil
	}
	if err := collectTables(document, ""); err != nil {
		return err
	}
	if raw, found := document["target"]; found {
		targets, ok := raw.(map[string]any)
		if !ok || len(targets) > 10000 {
			return errors.New("Cargo manifest target table is invalid")
		}
		for target, value := range targets {
			table, ok := value.(map[string]any)
			if !ok || target == "" {
				return errors.New("Cargo manifest target is invalid")
			}
			if err := collectTables(table, target); err != nil {
				return err
			}
		}
	}
	if len(expected) != len(payload.Deps) {
		return errors.New("Cargo manifest dependencies differ from publication metadata")
	}
	for _, dependency := range payload.Deps {
		alias, kind, target := dependency.Name, "normal", ""
		if dependency.ExplicitAlias != nil {
			alias = *dependency.ExplicitAlias
		}
		if dependency.Kind != nil && *dependency.Kind != "" {
			kind = *dependency.Kind
		}
		if dependency.Target != nil {
			target = *dependency.Target
		}
		identity := dependencyIdentity{Alias: alias, Package: dependency.Name, Kind: kind, Target: target}
		fields, found := expected[identity]
		if !found {
			return errors.New("Cargo manifest dependencies differ from publication metadata")
		}
		optional, defaultFeatures := false, true
		if dependency.Optional != nil {
			optional = *dependency.Optional
		}
		if dependency.Default != nil {
			defaultFeatures = *dependency.Default
		}
		declaredFeatures := slices.Clone(fields.Features)
		publishedFeatures := slices.Clone(dependency.Features)
		slices.Sort(declaredFeatures)
		slices.Sort(publishedFeatures)
		if normalizeRequirement(fields.Requirement) != normalizeRequirement(dependency.VersionReq) || fields.Optional != optional || fields.Default != defaultFeatures || !slices.Equal(declaredFeatures, publishedFeatures) {
			return errors.New("Cargo manifest dependency details differ from publication metadata")
		}
		if checkRegistry {
			registry := currentIndex
			if dependency.Registry != nil {
				registry = *dependency.Registry
			}
			if registry == "" || registry != fields.Registry {
				return errors.New("Cargo manifest dependency registry differs from publication metadata")
			}
		}
		delete(expected, identity)
	}
	return nil
}

// Cargo's default requirement is the caret requirement. Other spelling
// differences intentionally fail closed rather than claiming full equivalence.
func normalizeRequirement(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 1 && value[0] == '^' {
		first, _, _ := strings.Cut(value[1:], ",")
		if semver.IsValid("v" + strings.TrimSpace(first)) {
			return value[1:]
		}
	}
	return value
}
