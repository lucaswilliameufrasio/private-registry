package sessions

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"private-registry/internal/config"
)

func TestSessionStoresOnlyHashesAndRefreshesIdleExpiry(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	credentials, err := fixture.store.Create(ctx, fixture.userID, LevelStandard)
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials.BearerToken) != base64.RawURLEncoding.EncodedLen(tokenBytes) ||
		len(credentials.CSRFToken) != base64.RawURLEncoding.EncodedLen(tokenBytes) {
		t.Fatal("session bearer or CSRF token does not have the expected opaque format")
	}
	if credentials.Session.Level != LevelStandard || credentials.Session.MFAAuthenticatedAt != nil {
		t.Fatalf("unexpected initial session: %+v", credentials.Session)
	}

	var bearerHash, csrfHash, lastActivity string
	if err := fixture.db.QueryRowContext(ctx, `SELECT bearer_hash, csrf_hash, last_activity_at
		FROM registry_auth_sessions WHERE session_id = ?`, credentials.Session.ID).Scan(&bearerHash, &csrfHash, &lastActivity); err != nil {
		t.Fatal(err)
	}
	if bearerHash == credentials.BearerToken || csrfHash == credentials.CSRFToken || len(bearerHash) != 64 || len(csrfHash) != 64 {
		t.Fatal("database contains a raw session or CSRF token")
	}
	if lastActivity != credentials.Session.CreatedAt.Format(time.RFC3339Nano) {
		t.Fatalf("unexpected initial session activity time: %q", lastActivity)
	}

	fixture.now = fixture.now.Add(5 * time.Minute)
	if _, err := fixture.store.ValidateWithCSRF(ctx, credentials.BearerToken, "wrong-csrf-token"); !errors.Is(err, ErrCSRF) {
		t.Fatalf("invalid CSRF token was accepted: %v", err)
	}
	if err := fixture.db.QueryRowContext(ctx,
		"SELECT last_activity_at FROM registry_auth_sessions WHERE session_id = ?", credentials.Session.ID).Scan(&lastActivity); err != nil {
		t.Fatal(err)
	}
	if lastActivity != credentials.Session.CreatedAt.Format(time.RFC3339Nano) {
		t.Fatal("failed CSRF validation refreshed the session")
	}

	validated, err := fixture.store.ValidateWithCSRF(ctx, credentials.BearerToken, credentials.CSRFToken)
	if err != nil {
		t.Fatal(err)
	}
	if !validated.LastActivityAt.Equal(fixture.now) || !validated.IdleExpiresAt.Equal(fixture.now.Add(idleLifetime)) {
		t.Fatalf("valid request did not refresh inactivity deadline: %+v", validated)
	}
	if !validated.AbsoluteExpiresAt.Equal(credentials.Session.AbsoluteExpiresAt) {
		t.Fatal("activity changed the absolute expiration")
	}
}

func TestSessionAbsoluteAndIdleExpiryRevokeSessions(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	idleCredentials, err := fixture.store.Create(ctx, fixture.userID, LevelStandard)
	if err != nil {
		t.Fatal(err)
	}
	fixture.now = idleCredentials.Session.IdleExpiresAt.Add(time.Nanosecond)
	if _, err := fixture.store.Validate(ctx, idleCredentials.BearerToken); !errors.Is(err, ErrSessionUnavailable) {
		t.Fatalf("idle-expired session remained valid: %v", err)
	}
	var revokedAt sql.NullString
	if err := fixture.db.QueryRowContext(ctx,
		"SELECT revoked_at FROM registry_auth_sessions WHERE session_id = ?", idleCredentials.Session.ID).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if !revokedAt.Valid {
		t.Fatal("expired session was not marked revoked")
	}

	absoluteCredentials, err := fixture.store.Create(ctx, fixture.userID, LevelStandard)
	if err != nil {
		t.Fatal(err)
	}
	fixture.now = absoluteCredentials.Session.AbsoluteExpiresAt.Add(time.Nanosecond)
	if _, err := fixture.store.Validate(ctx, absoluteCredentials.BearerToken); !errors.Is(err, ErrSessionUnavailable) {
		t.Fatalf("absolute-expired session remained valid: %v", err)
	}
}

func TestSessionRotationAndAccountRevocation(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	initial, err := fixture.store.Create(ctx, fixture.userID, LevelEnrollmentOnly)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertActiveFactor(ctx, fixture.db, config.SQLite, fixture.userID); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(2 * time.Minute)
	rotated, err := fixture.store.Rotate(ctx, initial.BearerToken, LevelMFA)
	if err != nil {
		t.Fatal(err)
	}
	if initial.BearerToken == rotated.BearerToken || rotated.Session.Level != LevelMFA || rotated.Session.MFAAuthenticatedAt == nil {
		t.Fatalf("session rotation did not create a fresh MFA session: %+v", rotated.Session)
	}
	if _, err := fixture.store.Validate(ctx, initial.BearerToken); !errors.Is(err, ErrSessionUnavailable) {
		t.Fatalf("rotated bearer remained valid: %v", err)
	}
	if _, err := fixture.store.ValidateWithCSRF(ctx, rotated.BearerToken, rotated.CSRFToken); err != nil {
		t.Fatalf("new bearer did not validate: %v", err)
	}
	if err := fixture.store.RevokeUserSessions(ctx, fixture.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Validate(ctx, rotated.BearerToken); !errors.Is(err, ErrSessionUnavailable) {
		t.Fatalf("user-revoked bearer remained valid: %v", err)
	}
	if err := fixture.store.Revoke(ctx, rotated.BearerToken); err != nil {
		t.Fatalf("idempotent logout failed: %v", err)
	}
}

func TestMFAQualificationRequiresRestrictedSessionAndActiveFactor(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	if _, err := fixture.store.Create(ctx, fixture.userID, LevelMFA); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("direct MFA session creation was accepted: %v", err)
	}
	standard, err := fixture.store.Create(ctx, fixture.userID, LevelStandard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Rotate(ctx, standard.BearerToken, LevelMFA); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("standard session was promoted to MFA: %v", err)
	}
	challenge, err := fixture.store.Create(ctx, fixture.userID, LevelMFAChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Rotate(ctx, challenge.BearerToken, LevelMFA); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("MFA challenge without a registered factor was promoted: %v", err)
	}
	if err := insertActiveFactor(ctx, fixture.db, config.SQLite, fixture.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Rotate(ctx, challenge.BearerToken, LevelMFA); err != nil {
		t.Fatalf("eligible MFA challenge could not be rotated: %v", err)
	}
}

func TestPreAuthenticationSessionsHaveShortFixedLifetimes(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	enrollment, err := fixture.store.Create(ctx, fixture.userID, LevelEnrollmentOnly)
	if err != nil {
		t.Fatal(err)
	}
	if !enrollment.Session.AbsoluteExpiresAt.Equal(fixture.now.Add(enrollmentSessionLifetime)) ||
		!enrollment.Session.IdleExpiresAt.Equal(fixture.now.Add(enrollmentSessionLifetime)) {
		t.Fatalf("MFA enrollment session did not receive its short lifetime: %+v", enrollment.Session)
	}
	challenge, err := fixture.store.Create(ctx, fixture.userID, LevelMFAChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if !challenge.Session.AbsoluteExpiresAt.Equal(fixture.now.Add(mfaChallengeLifetime)) ||
		!challenge.Session.IdleExpiresAt.Equal(fixture.now.Add(mfaChallengeLifetime)) {
		t.Fatalf("MFA challenge session did not receive its short lifetime: %+v", challenge.Session)
	}
}

func TestInactiveUserAndInvalidLevelCannotCreateSessions(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	if _, err := fixture.store.Create(ctx, fixture.userID, Level("unknown")); !errors.Is(err, ErrInvalidLevel) {
		t.Fatalf("invalid session level was accepted: %v", err)
	}
	if _, err := fixture.db.ExecContext(ctx,
		"UPDATE registry_users SET status = 'suspended' WHERE user_id = ?", fixture.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Create(ctx, fixture.userID, LevelStandard); !errors.Is(err, ErrUserUnavailable) {
		t.Fatalf("inactive user was issued a session: %v", err)
	}
}

func TestMalformedBearerDoesNotExposeSessionState(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx := context.Background()
	for _, bearer := range []string{"", "short", strings.Repeat("x", 43)} {
		if _, err := fixture.store.Validate(ctx, bearer); !errors.Is(err, ErrSessionUnavailable) {
			t.Errorf("malformed bearer %q returned unexpected error: %v", bearer, err)
		}
	}
	if err := fixture.store.Revoke(ctx, "not-a-token"); err != nil {
		t.Fatalf("logout should be idempotent for an unknown bearer: %v", err)
	}
}
