package pub

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParsePubspecIdentity(t *testing.T) {
	name, version, err := ParsePubspecIdentity([]byte("name: fixture\nversion: 1.0.0+build.1\n"))
	if err != nil || name != "fixture" || version != "1.0.0+build.1" {
		t.Fatalf("identity differs: name=%q version=%q err=%v", name, version, err)
	}
	for _, manifest := range []string{
		"name: fixture\n",
		"version: 1.0.0\n",
		"name: Fixture\nversion: 1.0.0\n",
		"name: fixture\nversion: invalid\n",
		"name: fixture\nname: other\nversion: 1.0.0\n",
	} {
		if _, _, err := ParsePubspecIdentity([]byte(manifest)); err == nil {
			t.Fatalf("accepted invalid identity %q", manifest)
		}
	}
}

func TestValidatePubspec(t *testing.T) {
	for _, tt := range []struct {
		name  string
		body  string
		valid bool
	}{
		{"valid", "name: fixture\nversion: 1.0.0\ndependencies:\n  other: ^1.0.0\n", true},
		{"mismatch", "name: other\nversion: 1.0.0\n", false},
		{"duplicate", "name: fixture\nname: other\nversion: 1.0.0\n", false},
		{"nested duplicate", "name: fixture\nversion: 1.0.0\ndependencies:\n  a: 1\n  a: 2\n", false},
		{"alias", "name: fixture\nversion: 1.0.0\na: &x value\nb: *x\n", false},
		{"multiple documents", "name: fixture\nversion: 1.0.0\n---\nname: other\n", false},
		{"non-string identity", "name: fixture\nversion: 123\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePubspec([]byte(tt.body), "fixture", "1.0.0")
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v error=%v", tt.valid, err)
			}
		})
	}
}

func TestPubspecJSONPreservesHostedDependency(t *testing.T) {
	manifest := []byte("name: fixture\nversion: 1.0.0\ndependencies:\n  leaf:\n    hosted:\n      name: leaf\n      url: https://registry.example\n    version: ^1.0.0\n")
	encoded, err := PubspecJSON(manifest, "fixture", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Dependencies map[string]struct {
			Hosted struct {
				Name string `json:"name"`
				URL  string `json:"url"`
			} `json:"hosted"`
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(encoded, &data); err != nil || data.Dependencies["leaf"].Hosted.Name != "leaf" || data.Dependencies["leaf"].Version != "^1.0.0" {
		t.Fatalf("hosted Pub metadata differs: %v", err)
	}
}

func TestValidatePubspecLimits(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		[]byte(strings.Repeat("x", 1<<20+1)),
		[]byte("name: fixture\nversion: 1.0.0\ninvalid: \xff\n"),
		[]byte("name: fixture\nversion: 1.0.0\na: " + strings.Repeat("[", 70) + "0" + strings.Repeat("]", 70)),
	} {
		if err := ValidatePubspec(data, "fixture", "1.0.0"); err == nil {
			t.Fatal("accepted invalid or over-limit manifest")
		}
	}
}

func FuzzValidatePubspec(f *testing.F) {
	f.Add([]byte("name: fixture\nversion: 1.0.0\n"))
	f.Add([]byte("name: fixture\nname: other\nversion: 1.0.0\n"))
	f.Add([]byte("name: fixture\nversion: 1.0.0\na: &a [*a]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ValidatePubspec(data, "fixture", "1.0.0")
	})
}
