package cargo

import "testing"

func TestValidateManifestIndexFields(t *testing.T) {
	manifest := []byte("[package]\nname = \"fixture\"\nversion = \"1.0.0\"\nlinks = \"fixture_native\"\nrust-version = \"1.80\"\n")
	for _, tc := range []struct {
		name  string
		data  string
		valid bool
	}{
		{"matching", `{"links":"fixture_native","rust_version":"1.80"}`, true},
		{"different links", `{"links":"other","rust_version":"1.80"}`, false},
		{"different rust", `{"links":"fixture_native","rust_version":"1.81"}`, false},
		{"missing", `{"links":"fixture_native"}`, false},
		{"case collision", `{"links":"fixture_native","rust_version":"1.80","Rust_Version":"1.81"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateManifestIndexFields(manifest, []byte(tc.data))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
		})
	}
	if err := ValidateManifestIndexFields([]byte("[package]\nname = \"fixture\"\n"), []byte(`{"links":null,"rust_version":null}`)); err != nil {
		t.Fatal(err)
	}
}
