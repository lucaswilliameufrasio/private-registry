//go:build linux

package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestResolveMuiraIdentityRequiresExactActiveLink(t *testing.T) {
	fixture := newSQLiteFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	user := uuid.NewString()
	subject, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_users (user_id, display_name, email, created_at, updated_at) VALUES (?, 'Synthetic user', 'same@example.invalid', 'now', 'now')`, user); err != nil {
		t.Fatal(err)
	}
	issuer := "https://identity.example"
	if _, err := fixture.service.resolveMuiraIdentity(ctx, issuer, subject.String()); !errors.Is(err, ErrRejected) {
		t.Fatalf("unlinked Muira identity was accepted: %v", err)
	}
	if _, err := fixture.db.ExecContext(ctx, `INSERT INTO registry_external_identities (external_identity_id, user_id, provider_id, issuer, subject, created_at) VALUES (?, ?, 'muira', ?, ?, 'now')`, uuid.NewString(), user, issuer, subject.String()); err != nil {
		t.Fatal(err)
	}
	if got, err := fixture.service.resolveMuiraIdentity(ctx, issuer, subject.String()); err != nil || got != user {
		t.Fatalf("linked Muira identity rejected: %v", err)
	}
	for _, item := range []struct{ issuer, subject string }{
		{"https://other.example", subject.String()},
		{issuer, uuid.NewString()},
		{issuer, "same@example.invalid"},
	} {
		if _, err := fixture.service.resolveMuiraIdentity(ctx, item.issuer, item.subject); !errors.Is(err, ErrRejected) {
			t.Fatalf("wrong identity was accepted: %v", err)
		}
	}
	if _, err := fixture.db.ExecContext(ctx, `UPDATE registry_users SET status = 'suspended' WHERE user_id = ?`, user); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.resolveMuiraIdentity(ctx, issuer, subject.String()); !errors.Is(err, ErrRejected) {
		t.Fatalf("suspended Muira identity was accepted: %v", err)
	}
}
