package npm

import "testing"

func TestValidPublishVersion(t *testing.T) {
	for _, version := range []string{"1.0.0", "1.2.3-rc.1", "1.2.3+build", "9007199254740991.0.0"} {
		if !validPublishVersion(version) {
			t.Fatalf("supported version %q rejected", version)
		}
	}
	for _, version := range []string{"", "1.0", "v1.0.0", "01.0.0", "1.0.0+", "9007199254740992.0.0"} {
		if validPublishVersion(version) {
			t.Fatalf("invalid or unsupported version %q accepted", version)
		}
	}
}

func TestCompatibleArchiveVersion(t *testing.T) {
	for _, tc := range []struct {
		published string
		archived  string
		valid     bool
	}{
		{"1.0.0", "1.0.0", true},
		{"1.0.0", "1.0.0+build.1", true},
		{"1.0.0-rc.1", "1.0.0-rc.1+build", true},
		{"1.0.0", "1.0.1+build", false},
		{"1.0.0", "1.0.0+", false},
		{"1.0", "1.0+build", false},
		{"1.0.0", "v1.0.0+build", false},
	} {
		if got := compatibleArchiveVersion(tc.published, tc.archived); got != tc.valid {
			t.Fatalf("published=%q archived=%q got=%t", tc.published, tc.archived, got)
		}
	}
}
