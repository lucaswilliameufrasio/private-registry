package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	MemoryKiB           uint32 = 64 * 1024
	Iterations          uint32 = 3
	Parallelism         uint8  = 1
	SaltBytes                  = 16
	DerivedKeyBytes            = 32
	MaxPasswordBytes           = 4096
	MaxEncodedHashBytes        = 256
)

var dummySalt = []byte("private-registry-dummy")[:SaltBytes]

func Hash(value []byte) (string, error) {
	if len(value) > MaxPasswordBytes {
		return "", fmt.Errorf("password exceeds the supported byte limit")
	}
	salt := make([]byte, SaltBytes)
	defer clear(salt)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey(value, salt, Iterations, MemoryKiB, Parallelism, DerivedKeyBytes)
	defer clear(derivedKey)
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedKey := base64.RawStdEncoding.EncodeToString(derivedKey)
	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		MemoryKiB, Iterations, Parallelism, encodedSalt, encodedKey)
	return encoded, nil
}

// Verify always performs one Argon2id derivation for bounded inputs, including
// absent or malformed hashes. This keeps the missing-user login path close to
// the existing-user path without trusting parameters read from the database.
func Verify(encoded string, value []byte) bool {
	if len(value) > MaxPasswordBytes {
		return false
	}
	salt, expectedKey, valid := parseHash(encoded)
	if !valid {
		salt = dummySalt
		expectedKey = make([]byte, DerivedKeyBytes)
		defer clear(expectedKey)
	} else {
		defer clear(salt)
		defer clear(expectedKey)
	}
	actualKey := argon2.IDKey(value, salt, Iterations, MemoryKiB, Parallelism, DerivedKeyBytes)
	defer clear(actualKey)
	if !valid {
		return false
	}
	return subtle.ConstantTimeCompare(actualKey, expectedKey) == 1
}

func parseHash(encoded string) ([]byte, []byte, bool) {
	if len(encoded) > MaxEncodedHashBytes {
		return nil, nil, false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return nil, nil, false
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 {
		return nil, nil, false
	}
	if parameters[0] != fmt.Sprintf("m=%d", MemoryKiB) ||
		parameters[1] != fmt.Sprintf("t=%d", Iterations) ||
		parameters[2] != fmt.Sprintf("p=%d", Parallelism) {
		return nil, nil, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != SaltBytes {
		clear(salt)
		return nil, nil, false
	}
	derivedKey, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(derivedKey) != DerivedKeyBytes {
		clear(salt)
		clear(derivedKey)
		return nil, nil, false
	}
	return salt, derivedKey, true
}
