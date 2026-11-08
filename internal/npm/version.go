package npm

import (
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// validPublishVersion accepts a conservative full SemVer subset within the
// numeric range supported by the npm client; it is not a reservation policy.
func validPublishVersion(version string) bool {
	if len(version) == 0 || len(version) > 255 || !semver.IsValid("v"+version) {
		return false
	}
	core, _, _ := strings.Cut(version, "+")
	core, _, _ = strings.Cut(core, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil || number > 9007199254740991 {
			return false
		}
	}
	return true
}

// npm 11.19 publishes a SemVer without build metadata in the envelope while
// keeping it in the tarball manifest. This narrow equivalence does not validate
// the entire npm version contract or establish a uniqueness policy.
func compatibleArchiveVersion(published, archived string) bool {
	if published == archived {
		return true
	}
	if !strings.HasPrefix(archived, published+"+") || !semver.IsValid("v"+archived) {
		return false
	}
	return semver.Canonical("v"+archived) == "v"+published
}
