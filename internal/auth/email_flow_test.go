//go:build linux

package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"

	"private-registry/internal/email"
)

type recordingQueue struct {
	mu       sync.Mutex
	keys     []string
	messages []email.Message
}

func (q *recordingQueue) EnqueueTx(_ context.Context, _ *sql.Tx, key string, message email.Message) error {
	if err := message.Validate(); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.keys = append(q.keys, key)
	q.messages = append(q.messages, message)
	return nil
}

func (q *recordingQueue) last(t *testing.T, template email.Template) email.Message {
	t.Helper()
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := len(q.messages) - 1; i >= 0; i-- {
		if q.messages[i].Template == template {
			return q.messages[i]
		}
	}
	t.Fatalf("no %s message was queued", template)
	return email.Message{}
}

func (q *recordingQueue) count(template email.Template) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, m := range q.messages {
		if m.Template == template {
			n++
		}
	}
	return n
}

func linkToken(t *testing.T, link string) string {
	t.Helper()
	_, query, found := strings.Cut(link, "?")
	values, err := url.ParseQuery(query)
	if !found || err != nil || values.Get("token") == "" {
		t.Fatalf("link without token: %q", link)
	}
	return values.Get("token")
}

func TestEmailVerificationRecoveryAndNotices(t *testing.T) {
	ctx := context.Background()
	f := newSQLiteFixture(t)
	queue := &recordingQueue{}
	if err := f.service.RequestEmailVerification(ctx, f.addAccount(t, "early", "active", false, ""), "early@example.com"); !errors.Is(err, ErrEmailUnavailable) {
		t.Fatalf("email features must be off until enabled: %v", err)
	}
	if err := f.service.EnableEmail(queue, "https://registry.example"); err != nil {
		t.Fatal(err)
	}
	user := f.addAccount(t, "ana", "active", false, "")

	// No confirmed address: a recovery request is accepted and sends nothing.
	if err := f.service.RequestRecovery(ctx, "ana"); err != nil {
		t.Fatal(err)
	}
	if err := f.service.RequestRecovery(ctx, "nobody"); err != nil {
		t.Fatal(err)
	}
	if queue.count(email.TemplateRecovery) != 0 {
		t.Fatal("recovery sent to an unconfirmed address")
	}

	if err := f.service.RequestEmailVerification(ctx, user, "not an address"); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("invalid address: %v", err)
	}
	if err := f.service.RequestEmailVerification(ctx, user, "ana@example.com"); err != nil {
		t.Fatal(err)
	}
	pending, err := f.service.AccountEmailOf(ctx, user)
	if err != nil || pending.Verified || pending.Pending != "ana@example.com" {
		t.Fatalf("address must stay unconfirmed until the link is used: %+v %v", pending, err)
	}
	verification := queue.last(t, email.TemplateEmailVerification)
	if verification.To != "ana@example.com" || !strings.HasPrefix(verification.Data["link"], "https://registry.example/#/verify-email?token=prver_") {
		t.Fatalf("unexpected verification: %+v", verification)
	}
	token := linkToken(t, verification.Data["link"])
	if err := f.service.ConfirmEmail(ctx, token); err != nil {
		t.Fatal(err)
	}
	if err := f.service.ConfirmEmail(ctx, token); !errors.Is(err, ErrVerificationGone) {
		t.Fatalf("confirmation link reused: %v", err)
	}
	confirmed, _ := f.service.AccountEmailOf(ctx, user)
	if !confirmed.Verified || confirmed.Address != "ana@example.com" || confirmed.Pending != "" {
		t.Fatalf("address not confirmed: %+v", confirmed)
	}

	// Self-service recovery: one link per cooldown, password only.
	if err := f.service.RequestRecovery(ctx, "ANA"); err != nil {
		t.Fatal(err)
	}
	if err := f.service.RequestRecovery(ctx, "ana"); err != nil {
		t.Fatal(err)
	}
	if queue.count(email.TemplateRecovery) != 1 {
		t.Fatalf("recovery requests within the cooldown must send one link, sent %d", queue.count(email.TemplateRecovery))
	}
	recovery := queue.last(t, email.TemplateRecovery)
	var resetMFA int
	if err := f.db.QueryRowContext(ctx, `SELECT reset_mfa FROM registry_password_resets WHERE self_requested = 1`).Scan(&resetMFA); err != nil || resetMFA != 0 {
		t.Fatalf("self-requested recovery must not remove second factors: %d %v", resetMFA, err)
	}
	if err := f.service.CompleteRecovery(ctx, linkToken(t, recovery.Data["link"]), []byte("another-synthetic-password-1")); err != nil {
		t.Fatal(err)
	}
	notice := queue.last(t, email.TemplateSecurityNotice)
	if notice.To != "ana@example.com" || !strings.Contains(notice.Data["event_label"], "senha redefinida") {
		t.Fatalf("recovery notice: %+v", notice)
	}

	// Changing the address tells the previous one.
	if err := f.service.RequestEmailVerification(ctx, user, "ana.new@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := f.service.ConfirmEmail(ctx, linkToken(t, queue.last(t, email.TemplateEmailVerification).Data["link"])); err != nil {
		t.Fatal(err)
	}
	notice = queue.last(t, email.TemplateSecurityNotice)
	if notice.To != "ana@example.com" || !strings.Contains(notice.Data["event_label"], "e-mail") {
		t.Fatalf("address change notice must go to the previous address: %+v", notice)
	}

	// An administrator can send a recovery link without seeing it.
	admin := f.addAccount(t, "root", "active", true, "")
	issued, err := f.service.IssueRecoveryByEmail(ctx, admin, user, false)
	if err != nil || issued.Token != "" {
		t.Fatalf("emailed recovery: %+v %v", issued, err)
	}
	if got := queue.last(t, email.TemplateRecovery); got.To != "ana.new@example.com" {
		t.Fatalf("emailed recovery went to %q", got.To)
	}
	other := f.addAccount(t, "bia", "active", false, "")
	if _, err := f.service.IssueRecoveryByEmail(ctx, admin, other, false); !errors.Is(err, ErrNoVerifiedEmail) {
		t.Fatalf("recovery by email without a confirmed address: %v", err)
	}

	// A self-service request never cancels the administrator's link.
	if _, err := f.db.ExecContext(ctx, `UPDATE registry_password_resets SET created_at_ms = 0 WHERE self_requested = 1`); err != nil {
		t.Fatal(err)
	}
	if err := f.service.RequestRecovery(ctx, "ana"); err != nil {
		t.Fatal(err)
	}
	var revoked sql.NullInt64
	if err := f.db.QueryRowContext(ctx, `SELECT revoked_at_ms FROM registry_password_resets WHERE reset_id = ?`, issued.ID).Scan(&revoked); err != nil || revoked.Valid {
		t.Fatalf("administrator link was revoked by a self-service request: %v %v", revoked, err)
	}

	// Confirmation emails are limited per hour.
	limited := f.addAccount(t, "carla", "active", false, "")
	for i := 0; i < maxVerificationsHour; i++ {
		if err := f.service.RequestEmailVerification(ctx, limited, "carla@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.service.RequestEmailVerification(ctx, limited, "carla@example.com"); !errors.Is(err, ErrVerificationLimit) {
		t.Fatalf("confirmation limit: %v", err)
	}
}
