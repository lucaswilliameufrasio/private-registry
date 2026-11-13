package cargo

import "testing"

func TestValidateManifestIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest string
		valid    bool
	}{
		{"valid", "[package]\nname = \"synthetic\"\nversion = \"1.0.0\"\n", true},
		{"wrong name", "[package]\nname = \"other\"\nversion = \"1.0.0\"\n", false},
		{"wrong version", "[package]\nname = \"synthetic\"\nversion = \"1.0.1\"\n", false},
		{"duplicate key", "[package]\nname = \"synthetic\"\nname = \"other\"\nversion = \"1.0.0\"\n", false},
		{"workspace version", "[package]\nname = \"synthetic\"\nversion.workspace = true\n", false},
		{"comment is not identity", "# name = \"synthetic\"\n[package]\nversion = \"1.0.0\"\n", false},
		{"invalid TOML", "[package\nname = \"synthetic\"\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateManifestIdentity([]byte(tc.manifest), "synthetic", "1.0.0")
			if (err == nil) != tc.valid {
				t.Fatalf("manifest valid=%t, error=%v", tc.valid, err)
			}
		})
	}
}
