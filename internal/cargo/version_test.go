package cargo

import "testing"

func TestVersionIdentity(t *testing.T) {
	for _, tc := range []struct {
		version  string
		identity string
		valid    bool
	}{
		{"1.0.7", "1.0.7", true},
		{"1.0.7+build.5", "1.0.7", true},
		{"1.0.7-rc.1+build", "1.0.7-rc.1", true},
		{"1.0", "", false},
		{"1", "", false},
		{"01.0.0", "", false},
		{"1.0.0-01", "", false},
		{"v1.0.0", "", false},
		{"1.0.0+", "", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			identity, err := VersionIdentity(tc.version)
			if (err == nil) != tc.valid || identity != tc.identity {
				t.Fatalf("version identity=%q err=%v", identity, err)
			}
		})
	}
}
