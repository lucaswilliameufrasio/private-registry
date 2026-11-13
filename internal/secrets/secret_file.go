package secrets

import (
	"errors"
	"strings"
)

// ErrInvalidSecretFile is returned without revealing the path or contents.
var ErrInvalidSecretFile = errors.New("secret file is missing, unsafe or malformed")

const maxSecretFileBytes = 4096

// LoadSecretFile reads one operator-provisioned credential from a private
// regular file owned by the process user (no group/other access, no symlink,
// single hard link). A single trailing newline is tolerated; any other
// whitespace or control byte is rejected so that a truncated or mis-pasted
// credential fails at startup instead of at first use.
func LoadSecretFile(path string) (string, error) {
	contents, err := readPrivateFile(path, maxSecretFileBytes)
	if err != nil {
		return "", ErrInvalidSecretFile
	}
	defer clear(contents)
	value := strings.TrimSuffix(strings.TrimSuffix(string(contents), "\n"), "\r")
	if value == "" {
		return "", ErrInvalidSecretFile
	}
	for _, ch := range value {
		if ch <= ' ' || ch == 0x7f {
			return "", ErrInvalidSecretFile
		}
	}
	return value, nil
}
