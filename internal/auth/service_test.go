//go:build linux

package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"private-registry/internal/sessions"
)

func TestLoginUsesGenericErrorsAndIssuesStandardSession(t *testing.T) {
	fixture := newSQLiteFixture(t)
	fixture.addAccount(t, "normal.user", "active", false, "")
	ctx := context.Background()

	result, err := fixture.service.Login(ctx, " NORMAL.USER ", fixture.password, "192.0.2.20:4000")
	if err != nil {
		t.Fatal(err)
	}
	if result.Stage != StageAuthenticated || result.Credentials.Session.Level != sessions.LevelStandard {
		t.Fatalf("ordinary user received an unexpected login stage: %+v", result)
	}

	_, wrongPasswordErr := fixture.service.Login(ctx, "normal.user", []byte("synthetic-wrong-password"), "192.0.2.21")
	_, unknownUserErr := fixture.service.Login(ctx, "unknown.user", fixture.password, "192.0.2.22")
	if !errors.Is(wrongPasswordErr, ErrRejected) || !errors.Is(unknownUserErr, ErrRejected) {
		t.Fatalf("login errors disclosed account state: wrong=%v unknown=%v", wrongPasswordErr, unknownUserErr)
	}
}

func TestInstallationAndWorkspaceAdministratorsStartInRestrictedMFAStages(t *testing.T) {
	fixture := newSQLiteFixture(t)
	fixture.addAccount(t, "instance.admin", "active", true, "")
	fixture.addAccount(t, "workspace.owner", "active", false, "owner")
	fixture.addAccount(t, "workspace.admin", "active", false, "administrator")
	ctx := context.Background()

	for index, login := range []string{"instance.admin", "workspace.owner", "workspace.admin"} {
		result, err := fixture.service.Login(ctx, login, fixture.password, fmt.Sprintf("192.0.2.%d", 30+index))
		if err != nil {
			t.Fatalf("administrator %q failed login: %v", login, err)
		}
		if result.Stage != StageMFAEnrollment || result.Credentials.Session.Level != sessions.LevelEnrollmentOnly {
			t.Fatalf("administrator %q received a privileged session without MFA: %+v", login, result)
		}
	}
}

func TestInactiveAccountCannotAuthenticate(t *testing.T) {
	fixture := newSQLiteFixture(t)
	fixture.addAccount(t, "suspended.user", "suspended", false, "")
	_, err := fixture.service.Login(context.Background(), "suspended.user", fixture.password, "192.0.2.40")
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("suspended account was not rejected generically: %v", err)
	}
}

func TestSuccessfulLoginResetsAccountAttemptsAndTemporaryLimitIsEnforced(t *testing.T) {
	fixture := newSQLiteFixture(t)
	fixture.addAccount(t, "limited.user", "active", false, "")
	ctx := context.Background()
	for range 4 {
		_, err := fixture.service.Login(ctx, "limited.user", []byte("wrong-synthetic-password"), "192.0.2.41")
		if !errors.Is(err, ErrRejected) {
			t.Fatalf("invalid password returned unexpected error: %v", err)
		}
	}
	if _, err := fixture.service.Login(ctx, "limited.user", fixture.password, "192.0.2.41"); err != nil {
		t.Fatalf("correct password was denied before the limit: %v", err)
	}
	_, err := fixture.service.Login(ctx, "limited.user", []byte("wrong-synthetic-password"), "192.0.2.41")
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("successful login did not reset the account's failure window: %v", err)
	}
	for range 4 {
		_, err := fixture.service.Login(ctx, "limited.user", []byte("wrong-synthetic-password"), "192.0.2.41")
		if !errors.Is(err, ErrRejected) {
			t.Fatalf("invalid password returned unexpected error: %v", err)
		}
	}
	_, err = fixture.service.Login(ctx, "limited.user", fixture.password, "192.0.2.41")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("fifth failed login did not activate the temporary account limit: %v", err)
	}
}

func TestMFAEnrollmentChallengeAndTOTPCompletion(t *testing.T) {
	fixture := newSQLiteFixture(t)
	fixture.addAccount(t, "mfa.admin", "active", true, "")
	ctx := context.Background()

	enrollmentLogin, err := fixture.service.Login(ctx, "mfa.admin", fixture.password, "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if enrollmentLogin.Stage != StageMFAEnrollment {
		t.Fatalf("admin did not enter restricted MFA enrollment: %+v", enrollmentLogin)
	}
	enrollment, err := fixture.service.BeginMFAEnrollment(ctx, enrollmentLogin.Credentials.BearerToken)
	if err != nil {
		t.Fatal(err)
	}
	repeatedEnrollment, err := fixture.service.BeginMFAEnrollment(ctx, enrollmentLogin.Credentials.BearerToken)
	if err != nil {
		t.Fatal(err)
	}
	if repeatedEnrollment.Secret != enrollment.Secret {
		t.Fatal("repeated enrollment did not reuse the pending secret")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)

	confirmationCode := generateTOTPCode(secret, time.Now().Unix()/30)
	completedEnrollment, err := fixture.service.CompleteMFAEnrollment(
		ctx, enrollmentLogin.Credentials.BearerToken, confirmationCode, "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if len(completedEnrollment.RecoveryCodes) != 10 || completedEnrollment.Credentials.Session.Level != sessions.LevelMFA {
		t.Fatalf("enrollment did not yield a full MFA session and recovery kit: %+v", completedEnrollment)
	}
	if _, err := fixture.service.BeginMFAEnrollment(ctx, completedEnrollment.Credentials.BearerToken); !errors.Is(err, ErrRejected) {
		t.Fatalf("fully authenticated session could still use enrollment-only flow: %v", err)
	}

	challengeLogin, err := fixture.service.Login(ctx, "mfa.admin", fixture.password, "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if challengeLogin.Stage != StageMFAChallenge || challengeLogin.Credentials.Session.Level != sessions.LevelMFAChallenge {
		t.Fatalf("admin with enrolled TOTP skipped the MFA challenge: %+v", challengeLogin)
	}
	nextCode := generateTOTPCode(secret, time.Now().Unix()/30+1)
	fullSession, err := fixture.service.CompleteMFA(
		ctx, challengeLogin.Credentials.BearerToken, nextCode, "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if fullSession.Session.Level != sessions.LevelMFA || fullSession.BearerToken == challengeLogin.Credentials.BearerToken {
		t.Fatalf("MFA challenge was not rotated into a full session: %+v", fullSession.Session)
	}
}

func TestStandardSessionMustStepDownBeforeVoluntaryMFAEnrollment(t *testing.T) {
	fixture := newSQLiteFixture(t)
	fixture.addAccount(t, "voluntary.user", "active", false, "")
	ctx := context.Background()
	login, err := fixture.service.Login(ctx, "voluntary.user", fixture.password, "192.0.2.70")
	if err != nil {
		t.Fatal(err)
	}
	if login.Credentials.Session.Level != sessions.LevelStandard {
		t.Fatalf("ordinary user did not receive a standard session: %+v", login.Credentials.Session)
	}

	started, err := fixture.service.BeginVoluntaryMFAEnrollment(ctx, login.Credentials.BearerToken)
	if err != nil {
		t.Fatal(err)
	}
	if started.Credentials.Session.Level != sessions.LevelEnrollmentOnly || started.Enrollment.Secret == "" {
		t.Fatalf("voluntary enrollment did not return a restricted session and pending factor: %+v", started)
	}
	if _, err := fixture.service.ValidateSession(ctx, login.Credentials.BearerToken); !errors.Is(err, sessions.ErrSessionUnavailable) {
		t.Fatalf("pre-enrollment standard bearer remained valid: %v", err)
	}
	repeatedEnrollment, err := fixture.service.BeginMFAEnrollment(ctx, started.Credentials.BearerToken)
	if err != nil {
		t.Fatal(err)
	}
	if repeatedEnrollment.Secret != started.Enrollment.Secret {
		t.Fatal("restricted enrollment session did not retain its pending factor")
	}

	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(started.Enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	code := generateTOTPCode(secret, time.Now().Unix()/30)
	completed, err := fixture.service.CompleteMFAEnrollment(ctx, started.Credentials.BearerToken, code, "192.0.2.70")
	if err != nil {
		t.Fatal(err)
	}
	if completed.Credentials.Session.Level != sessions.LevelMFA || len(completed.RecoveryCodes) != 10 {
		t.Fatalf("voluntary enrollment did not produce a full MFA session: %+v", completed)
	}
	if _, err := fixture.service.BeginVoluntaryMFAEnrollment(ctx, completed.Credentials.BearerToken); !errors.Is(err, ErrRejected) {
		t.Fatalf("session with an active MFA factor started another initial enrollment: %v", err)
	}
}

func TestPasswordHashAdmissionRejectsExcessConcurrencyWithoutQueue(t *testing.T) {
	fixture := newSQLiteFixture(t)
	service := fixture.service
	started := make(chan struct{}, maxConcurrentPasswordChecks)
	release := make(chan struct{})
	service.verify = func(_ string, _ []byte) bool {
		started <- struct{}{}
		<-release
		return false
	}

	const callers = maxConcurrentPasswordChecks
	results := make(chan error, callers)
	var waitGroup sync.WaitGroup
	for index := 0; index < callers; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			loginName := fmt.Sprintf("unknown-%d", index)
			_, err := service.Login(context.Background(), loginName, fixture.password, fmt.Sprintf("192.0.2.%d", 60+index))
			results <- err
		}(index)
	}
	for range callers {
		<-started
	}
	_, saturatedErr := service.Login(context.Background(), "third.unknown", fixture.password, "192.0.2.62")
	if !errors.Is(saturatedErr, ErrBusy) {
		close(release)
		waitGroup.Wait()
		t.Fatalf("saturated Argon2 admission did not reject immediately: %v", saturatedErr)
	}
	close(release)
	waitGroup.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, ErrRejected) {
			t.Errorf("bounded password check returned unexpected result: %v", err)
		}
	}
}

func generateTOTPCode(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := int(digest[len(digest)-1] & 0x0f)
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}
