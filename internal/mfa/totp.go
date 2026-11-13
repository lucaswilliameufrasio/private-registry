package mfa

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
)

const (
	totpPeriodSeconds = int64(30)
	totpDigits        = 6
	totpSecretBytes   = 20
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func generateTOTPCode(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))

	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := int(digest[len(digest)-1] & 0x0f)
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for range totpDigits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%modulus)
}

func matchingTOTPCode(secret []byte, code string, unixSeconds int64) (int64, bool) {
	if !validTOTPCode(code) || unixSeconds < 0 {
		return 0, false
	}
	currentStep := unixSeconds / totpPeriodSeconds
	matchedStep := int64(-1)
	for step := currentStep - 1; step <= currentStep+1; step++ {
		if step < 0 {
			continue
		}
		expected := generateTOTPCode(secret, step)
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 && step > matchedStep {
			matchedStep = step
		}
	}
	if matchedStep < 0 {
		return 0, false
	}
	return matchedStep, true
}

func validTOTPCode(code string) bool {
	if len(code) != totpDigits {
		return false
	}
	for index := 0; index < len(code); index++ {
		if code[index] < '0' || code[index] > '9' {
			return false
		}
	}
	return true
}

func encodeTOTPSecret(secret []byte) string {
	return base32Encoding.EncodeToString(secret)
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	decoded, err := base32Encoding.DecodeString(secret)
	if err != nil || len(decoded) != totpSecretBytes {
		return nil, ErrMFAStorage
	}
	return decoded, nil
}
