// Package pub contains experimental validation boundaries for Pub packages.
// These functions do not authorize, publish, or serve a package.
package pub

import (
	"errors"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

var packageNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var fullVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// ValidateName accepts a conservative subset of names for new Pub packages.
// It does not establish namespace ownership or compatibility with every SDK.
func ValidateName(name string) error {
	if !packageNamePattern.MatchString(name) || strings.HasSuffix(name, "_") || strings.Contains(name, "__") {
		return errors.New("Pub package name is invalid")
	}
	return nil
}

// VersionIdentity strips build metadata for collision checks. It does not
// establish Pub's complete version ordering or client normalization parity.
func VersionIdentity(version string) (string, error) {
	if len(version) < 5 || len(version) > 255 || !fullVersionPattern.MatchString(version) || !semver.IsValid("v"+version) {
		return "", errors.New("Pub package version is invalid")
	}
	identity, _, _ := strings.Cut(version, "+")
	return identity, nil
}
