package cargo

import (
	"errors"
	"strings"

	"golang.org/x/mod/semver"
)

// VersionIdentity validates a full SemVer 2.0.0 crate version and returns the
// version identity used for uniqueness, excluding build metadata as required by
// the Cargo index contract. This does not reserve the identity in storage.
func VersionIdentity(version string) (string, error) {
	if len(version) == 0 || len(version) > 255 || !semver.IsValid("v"+version) {
		return "", errors.New("Cargo version is not valid SemVer")
	}
	base, _, _ := strings.Cut(version, "+")
	if semver.Canonical("v"+version) != "v"+base {
		return "", errors.New("Cargo version must use full canonical SemVer")
	}
	return base, nil
}
