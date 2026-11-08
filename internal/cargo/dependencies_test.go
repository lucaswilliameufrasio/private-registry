package cargo

import "testing"

func TestValidateManifestDependencyIdentities(t *testing.T) {
	manifest := []byte("[package]\nname = \"parent\"\nversion = \"1.0.0\"\n[dependencies.alias]\npackage = \"original\"\nversion = \"1\"\n[target.'cfg(windows)'.build-dependencies]\nhelper = \"2\"\n")
	for _, tc := range []struct {
		name     string
		metadata string
		valid    bool
	}{
		{"matching", `{"deps":[{"name":"original","explicit_name_in_toml":"alias","version_req":"1"},{"name":"helper","version_req":"2","kind":"build","target":"cfg(windows)"}]}`, true},
		{"wrong package", `{"deps":[{"name":"wrong","explicit_name_in_toml":"alias","version_req":"1"},{"name":"helper","version_req":"2","kind":"build","target":"cfg(windows)"}]}`, false},
		{"wrong target", `{"deps":[{"name":"original","explicit_name_in_toml":"alias","version_req":"1"},{"name":"helper","version_req":"2","kind":"build"}]}`, false},
		{"missing", `{"deps":[{"name":"original","explicit_name_in_toml":"alias","version_req":"1"}]}`, false},
		{"duplicate", `{"deps":[{"name":"original","explicit_name_in_toml":"alias","version_req":"1"},{"name":"original","explicit_name_in_toml":"alias","version_req":"1"}]}`, false},
		{"wrong requirement", `{"deps":[{"name":"original","explicit_name_in_toml":"alias","version_req":"2"},{"name":"helper","version_req":"2","kind":"build","target":"cfg(windows)"}]}`, false},
		{"wrong optional", `{"deps":[{"name":"original","explicit_name_in_toml":"alias","version_req":"1","optional":true},{"name":"helper","version_req":"2","kind":"build","target":"cfg(windows)"}]}`, false},
		{"wrong defaults", `{"deps":[{"name":"original","explicit_name_in_toml":"alias","version_req":"1","default_features":false},{"name":"helper","version_req":"2","kind":"build","target":"cfg(windows)"}]}`, false},
		{"wrong features", `{"deps":[{"name":"original","explicit_name_in_toml":"alias","version_req":"1","features":["extra"]},{"name":"helper","version_req":"2","kind":"build","target":"cfg(windows)"}]}`, false},
		{"caret default", `{"deps":[{"name":"original","explicit_name_in_toml":"alias","version_req":"^1"},{"name":"helper","version_req":"^2","kind":"build","target":"cfg(windows)"}]}`, true},
		{"invalid caret comparator", `{"deps":[{"name":"original","explicit_name_in_toml":"alias","version_req":"^>=1"},{"name":"helper","version_req":"2","kind":"build","target":"cfg(windows)"}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateManifestDependencyIdentities(manifest, []byte(tc.metadata))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
		})
	}
}

func TestNormalizeRequirementDoesNotStripCaretFromComparators(t *testing.T) {
	if normalizeRequirement("^>=1") == normalizeRequirement(">=1") {
		t.Fatal("invalid caret comparator was treated as a valid comparator")
	}
	if normalizeRequirement("^1.*") == normalizeRequirement("1.*") {
		t.Fatal("unvalidated caret wildcard was normalized")
	}
	if normalizeRequirement("^1.2") != normalizeRequirement("1.2") {
		t.Fatal("valid caret shorthand was not normalized")
	}
}

func TestValidateManifestDependencyRegistries(t *testing.T) {
	const current = "sparse+https://registry.example/index/"
	const defaultIndex = "https://github.com/rust-lang/crates.io-index"
	manifest := []byte("[dependencies.private_alias]\npackage = \"private_dep\"\nversion = \"1\"\nregistry-index = \"" + current + "\"\n[dependencies.public_dep]\nversion = \"2\"\n")
	for _, tc := range []struct {
		name     string
		metadata string
		valid    bool
	}{
		{"current and public", `{"deps":[{"name":"private_dep","explicit_name_in_toml":"private_alias","version_req":"1"},{"name":"public_dep","version_req":"2","registry":"https://github.com/rust-lang/crates.io-index"}]}`, true},
		{"private substituted", `{"deps":[{"name":"private_dep","explicit_name_in_toml":"private_alias","version_req":"1","registry":"https://example.invalid/index"},{"name":"public_dep","version_req":"2","registry":"https://github.com/rust-lang/crates.io-index"}]}`, false},
		{"public marked current", `{"deps":[{"name":"private_dep","explicit_name_in_toml":"private_alias","version_req":"1"},{"name":"public_dep","version_req":"2"}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateManifestDependencies(manifest, []byte(tc.metadata), current, defaultIndex)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
		})
	}
}
