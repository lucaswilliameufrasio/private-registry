package npm

import (
	"strings"
	"testing"
)

func TestValidDistTagConservativeSubset(t *testing.T) {
	for _, tag := range []string{"latest", "next", "release-1", "vnext", "alpha.1", "a_b"} {
		if !validTag(tag) {
			t.Errorf("valid tag %q rejected", tag)
		}
	}
	for _, tag := range []string{"", "1.0.0", "v1.0.0", "v1.0.0-rc.1", "UPPER", "a/b", "a b", "_tag", strings.Repeat("a", 129)} {
		if validTag(tag) {
			t.Errorf("invalid tag %q accepted", tag)
		}
	}
}
