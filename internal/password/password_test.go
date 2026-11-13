package password

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	value := []byte("synthetic-password-not-for-use")
	encoded, err := Hash(value)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(encoded, value) {
		t.Fatal("correct password was rejected")
	}
	if Verify(encoded, []byte("different-synthetic-password")) {
		t.Fatal("incorrect password was accepted")
	}
	if Verify("", value) {
		t.Fatal("missing password hash was accepted")
	}
}

func TestVerifyRejectsUnsupportedAndMalformedHashParameters(t *testing.T) {
	cases := []string{
		"$argon2id$v=16$m=65536,t=3,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=999999999,t=3,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=999999999,p=1$c2FsdA$aGFzaA",
		"$scrypt$v=19$m=65536,t=3,p=1$c2FsdA$aGFzaA",
	}
	for _, encoded := range cases {
		if _, _, valid := parseHash(encoded); valid {
			t.Errorf("malformed or unsupported hash parameters were accepted: %q", encoded)
		}
	}
}

func TestParseHashRejectsOversizedEncodedValue(t *testing.T) {
	if _, _, valid := parseHash(strings.Repeat("$", MaxEncodedHashBytes+1)); valid {
		t.Fatal("oversized encoded hash was accepted")
	}
}

func TestHashRejectsOversizedInput(t *testing.T) {
	if _, err := Hash([]byte(strings.Repeat("x", MaxPasswordBytes+1))); err == nil {
		t.Fatal("oversized password was hashed")
	}
	if Verify("", []byte(strings.Repeat("x", MaxPasswordBytes+1))) {
		t.Fatal("oversized password was accepted")
	}
}
