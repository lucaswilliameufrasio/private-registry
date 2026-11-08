package cargo

import "testing"

func TestValidateManifestFeatures(t *testing.T) {
	manifest := []byte("[package]\nname = \"synthetic\"\nversion = \"1.0.0\"\n[features]\nfast = [\"dep:alias\", \"alias?/extra\"]\nempty = []\n")
	for _, tc := range []struct {
		name     string
		metadata string
		valid    bool
	}{
		{"matching reordered", `{"features":{"fast":["alias?/extra","dep:alias"],"empty":[]}}`, true},
		{"different", `{"features":{"fast":["dep:alias"],"empty":[]}}`, false},
		{"extra", `{"features":{"fast":["dep:alias","alias?/extra"],"empty":[],"extra":[]}}`, false},
		{"null array", `{"features":{"fast":["dep:alias","alias?/extra"],"empty":null}}`, false},
		{"duplicate json", `{"features":{},"features":{}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateManifestFeatures(manifest, []byte(tc.metadata))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t err=%v", tc.valid, err)
			}
		})
	}
}
