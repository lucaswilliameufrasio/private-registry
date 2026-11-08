package cargo

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SparseIndexPath returns the canonical lowercase sparse index path for an
// Cargo name within the verified case-mapping subset. The pinned Cargo client
// slices UTF-8 bytes at fixed positions; unsafe boundaries and unverified
// non-ASCII case mappings are rejected rather than producing a wrong path.
// This is not an authorization check or an admission policy.
func SparseIndexPath(name string) (string, error) {
	if !safeCrateName(name) {
		return "", errors.New("Cargo package name is invalid")
	}
	lower := strings.ToLower(name)
	switch len(lower) {
	case 1:
		return "1/" + lower, nil
	case 2:
		return "2/" + lower, nil
	case 3:
		if !utf8.ValidString(lower[:1]) {
			return "", errors.New("Cargo package name has an unsafe sparse index boundary")
		}
		return "3/" + lower[:1] + "/" + lower, nil
	default:
		if !utf8.ValidString(lower[:2]) || !utf8.ValidString(lower[2:4]) {
			return "", errors.New("Cargo package name has an unsafe sparse index boundary")
		}
		return lower[:2] + "/" + lower[2:4] + "/" + lower, nil
	}
}

func safeCrateName(name string) bool {
	if len(name) < 1 || len(name) > 255 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r > unicode.MaxASCII && unicode.ToLower(r) != r {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && !unicode.Is(unicode.Other_Alphabetic, r) && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
