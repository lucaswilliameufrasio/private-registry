//go:build linux

package mfa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTOTPUsesRFC6238SHA1Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := []struct {
		unixSeconds int64
		want        string
	}{
		{unixSeconds: 59, want: "287082"},
		{unixSeconds: 1111111109, want: "081804"},
		{unixSeconds: 1111111111, want: "050471"},
		{unixSeconds: 1234567890, want: "005924"},
		{unixSeconds: 2000000000, want: "279037"},
		{unixSeconds: 20000000000, want: "353130"},
	}
	for _, testCase := range cases {
		got := generateTOTPCode(secret, testCase.unixSeconds/totpPeriodSeconds)
		if got != testCase.want {
			t.Errorf("TOTP at %d seconds = %q, want %q", testCase.unixSeconds, got, testCase.want)
		}
	}
}

func TestEnrollmentConfirmationReplayProtectionAndRecoveryCodes(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()

	enrollment, err := fixture.service.BeginEnrollment(ctx, fixture.userID)
	if err != nil {
		t.Fatal(err)
	}
	if !enrollment.ExpiresAt.Equal(fixture.clockNow.Add(enrollmentLifetime)) {
		t.Fatalf("unexpected enrollment expiry: %s", enrollment.ExpiresAt)
	}
	parsedURL, err := url.Parse(enrollment.OTPAuthURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsedURL.Scheme != "otpauth" || parsedURL.Host != "totp" || parsedURL.Query().Get("issuer") != totpIssuer {
		t.Fatalf("unexpected OTPAuth URL: %q", enrollment.OTPAuthURL)
	}
	if parsedURL.Query().Get("secret") != enrollment.Secret || parsedURL.Query().Get("digits") != "6" || parsedURL.Query().Get("period") != "30" {
		t.Fatalf("OTPAuth URL does not match enrollment parameters: %q", enrollment.OTPAuthURL)
	}

	repeatedEnrollment, err := fixture.service.BeginEnrollment(ctx, fixture.userID)
	if err != nil {
		t.Fatal(err)
	}
	if repeatedEnrollment.Secret != enrollment.Secret || !repeatedEnrollment.ExpiresAt.Equal(enrollment.ExpiresAt) {
		t.Fatal("repeated enrollment did not return the existing pending seed")
	}

	var envelope []byte
	if err := fixture.db.QueryRowContext(ctx,
		"SELECT secret_envelope FROM registry_totp_credentials WHERE user_id = ?", fixture.userID).Scan(&envelope); err != nil {
		t.Fatal(err)
	}
	seed, err := decodeTOTPSecret(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	if bytes.Contains(envelope, []byte(enrollment.Secret)) || bytes.Contains(envelope, seed) {
		t.Fatal("database contains the pending TOTP seed in plaintext")
	}
	decrypted, err := fixture.key.Open(envelope, encryptionContext(fixture.userID))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, seed) {
		clear(decrypted)
		t.Fatal("stored TOTP envelope did not decrypt to the enrollment seed")
	}
	clear(decrypted)

	invalidCode := nonmatchingCode(seed, fixture.clockNow.Unix())
	if _, err := fixture.service.ConfirmEnrollment(ctx, fixture.userID, invalidCode); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("invalid confirmation code was accepted: %v", err)
	}
	active, err := fixture.service.HasActiveFactor(ctx, fixture.userID)
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("invalid TOTP confirmation activated the factor")
	}

	currentStep := fixture.clockNow.Unix() / totpPeriodSeconds
	confirmationCode := generateTOTPCode(seed, currentStep)
	recoveryCodes, err := fixture.service.ConfirmEnrollment(ctx, fixture.userID, confirmationCode)
	if err != nil {
		t.Fatal(err)
	}
	if len(recoveryCodes) != recoveryCodeCount {
		t.Fatalf("got %d recovery codes, want %d", len(recoveryCodes), recoveryCodeCount)
	}
	if _, err := fixture.service.ConfirmEnrollment(ctx, fixture.userID, confirmationCode); !errors.Is(err, ErrFactorEnrolled) {
		t.Fatalf("active factor was re-confirmed: %v", err)
	}
	active, err = fixture.service.HasActiveFactor(ctx, fixture.userID)
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("confirmed TOTP factor is not active")
	}

	verified, err := fixture.service.VerifyTOTP(ctx, fixture.userID, confirmationCode)
	if err != nil {
		t.Fatal(err)
	}
	if verified {
		t.Fatal("confirmation code was replayed after enrollment")
	}
	fixture.clockNow = fixture.clockNow.Add(time.Duration(totpPeriodSeconds) * time.Second)
	nextCode := generateTOTPCode(seed, fixture.clockNow.Unix()/totpPeriodSeconds)
	verified, err = fixture.service.VerifyTOTP(ctx, fixture.userID, nextCode)
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("next valid TOTP step was rejected")
	}
	verified, err = fixture.service.VerifyTOTP(ctx, fixture.userID, nextCode)
	if err != nil {
		t.Fatal(err)
	}
	if verified {
		t.Fatal("valid TOTP step was accepted more than once")
	}

	consumed, err := fixture.service.ConsumeRecoveryCode(ctx, fixture.userID, strings.ToUpper(recoveryCodes[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("unused recovery code was rejected")
	}
	consumed, err = fixture.service.ConsumeRecoveryCode(ctx, fixture.userID, recoveryCodes[0])
	if err != nil {
		t.Fatal(err)
	}
	if consumed {
		t.Fatal("recovery code was consumed more than once")
	}

	var storedHash string
	var consumedAt sql.NullString
	compact, ok := normalizeRecoveryCode(recoveryCodes[0])
	if !ok {
		t.Fatal("generated recovery code was not valid")
	}
	digest := sha256.Sum256([]byte(compact))
	if err := fixture.db.QueryRowContext(ctx, `SELECT code_hash, consumed_at
		FROM registry_mfa_recovery_codes WHERE user_id = ? AND code_hash = ?`, fixture.userID, hex.EncodeToString(digest[:])).Scan(&storedHash, &consumedAt); err != nil {
		t.Fatal(err)
	}
	if storedHash != hex.EncodeToString(digest[:]) || !consumedAt.Valid {
		t.Fatal("recovery code was not stored as a consumed one-way hash")
	}
	if storedHash == compact || len(storedHash) != sha256.Size*2 {
		t.Fatal("recovery code was stored in plaintext")
	}

	var auditEvents int
	if err := fixture.db.QueryRowContext(ctx,
		"SELECT count(*) FROM registry_audit_events WHERE actor_user_id = ? AND action LIKE 'mfa.%'", fixture.userID).Scan(&auditEvents); err != nil {
		t.Fatal(err)
	}
	if auditEvents != 2 {
		t.Fatalf("got %d MFA audit events, want enrollment and one recovery use", auditEvents)
	}
}

func TestEnrollmentExpiresAndCorruptCiphertextFailsClosed(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()

	first, err := fixture.service.BeginEnrollment(ctx, fixture.userID)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clockNow = first.ExpiresAt.Add(time.Nanosecond)
	if _, err := fixture.service.ConfirmEnrollment(ctx, fixture.userID, "000000"); !errors.Is(err, ErrEnrollmentExpired) {
		t.Fatalf("expired TOTP enrollment was not rejected: %v", err)
	}
	second, err := fixture.service.BeginEnrollment(ctx, fixture.userID)
	if err != nil {
		t.Fatal(err)
	}
	if first.Secret == second.Secret || !second.ExpiresAt.After(fixture.clockNow) {
		t.Fatal("expired enrollment was not replaced with a fresh, bounded enrollment")
	}

	var envelope []byte
	if err := fixture.db.QueryRowContext(ctx,
		"SELECT secret_envelope FROM registry_totp_credentials WHERE user_id = ?", fixture.userID).Scan(&envelope); err != nil {
		t.Fatal(err)
	}
	envelope[len(envelope)-1] ^= 0x01
	if _, err := fixture.db.ExecContext(ctx,
		"UPDATE registry_totp_credentials SET secret_envelope = ? WHERE user_id = ?", envelope, fixture.userID); err != nil {
		t.Fatal(err)
	}
	seed, err := decodeTOTPSecret(second.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	code := generateTOTPCode(seed, fixture.clockNow.Unix()/totpPeriodSeconds)
	if _, err := fixture.service.ConfirmEnrollment(ctx, fixture.userID, code); !errors.Is(err, ErrEncryption) {
		t.Fatalf("tampered encrypted seed did not fail closed: %v", err)
	}
	active, err := fixture.service.HasActiveFactor(ctx, fixture.userID)
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("tampered TOTP seed activated a factor")
	}
}

func TestDestroyedMasterKeyCannotConfirmEnrollment(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	enrollment, err := fixture.service.BeginEnrollment(ctx, fixture.userID)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := decodeTOTPSecret(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	code := generateTOTPCode(seed, fixture.clockNow.Unix()/totpPeriodSeconds)
	fixture.key.Destroy()
	if _, err := fixture.service.ConfirmEnrollment(ctx, fixture.userID, code); !errors.Is(err, ErrEncryption) {
		t.Fatalf("destroyed master key did not fail closed: %v", err)
	}
	active, err := fixture.service.HasActiveFactor(ctx, fixture.userID)
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("factor was activated without the master key")
	}
}

func TestConcurrentRecoveryCodeConsumptionSucceedsOnlyOnce(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	enrollment, err := fixture.service.BeginEnrollment(ctx, fixture.userID)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := decodeTOTPSecret(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	code := generateTOTPCode(seed, fixture.clockNow.Unix()/totpPeriodSeconds)
	recoveryCodes, err := fixture.service.ConfirmEnrollment(ctx, fixture.userID, code)
	if err != nil {
		t.Fatal(err)
	}

	const callers = 8
	start := make(chan struct{})
	type result struct {
		consumed bool
		err      error
	}
	results := make(chan result, callers)
	var waitGroup sync.WaitGroup
	for range callers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			consumed, err := fixture.service.ConsumeRecoveryCode(ctx, fixture.userID, recoveryCodes[0])
			results <- result{consumed: consumed, err: err}
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)

	successes := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent recovery consumption failed: %v", result.err)
		}
		if result.consumed {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("recovery code was consumed %d times, want exactly once", successes)
	}
}

func TestInactiveUserCannotEnrollMFA(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	userID, err := insertActiveTestUser(ctx, fixture.db, "mfa.inactive")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.ExecContext(ctx,
		"UPDATE registry_users SET status = 'suspended' WHERE user_id = ?", userID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.BeginEnrollment(ctx, userID); !errors.Is(err, ErrUserUnavailable) {
		t.Fatalf("suspended user was allowed to enroll MFA: %v", err)
	}
}

func nonmatchingCode(secret []byte, unixSeconds int64) string {
	for candidate := 0; candidate < 1000000; candidate++ {
		code := fmt.Sprintf("%06d", candidate)
		_, matched := matchingTOTPCode(secret, code, unixSeconds)
		if !matched {
			return code
		}
	}
	return "000000"
}
