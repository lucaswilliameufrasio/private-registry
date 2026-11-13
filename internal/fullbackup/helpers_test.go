package fullbackup_test

import (
	"crypto/sha256"
	"encoding/hex"
)

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
