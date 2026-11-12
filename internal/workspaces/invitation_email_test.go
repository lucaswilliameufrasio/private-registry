package workspaces

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"testing"

	"private-registry/internal/config"
	"private-registry/internal/email"
)

type capturedEmail struct {
	key     string
	message email.Message
}

type captureQueue struct{ sent []capturedEmail }

func (q *captureQueue) EnqueueTx(_ context.Context, _ *sql.Tx, key string, message email.Message) error {
	if err := message.Validate(); err != nil {
		return err
	}
	q.sent = append(q.sent, capturedEmail{key, message})
	return nil
}

func TestEmailedInvitationConfirmsTheRedeemedAddress(t *testing.T) {
	ctx, db, _ := openSQLite(t)
	service, err := New(db, config.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	adminID := seedUser(t, ctx, db, config.SQLite, "active", "admin@example.invalid")
	seedInstanceAdmin(t, ctx, db, config.SQLite, adminID)
	workspace, err := service.CreateWorkspace(ctx, adminID, "mailed", "Mailed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateInvitationFor(ctx, adminID, workspace.ID, RoleMember, 0, "new@example.com"); !errors.Is(err, ErrEmailUnavailable) {
		t.Fatalf("emailed invitation without email delivery: %v", err)
	}
	queue := &captureQueue{}
	if err := service.EnableEmail(queue, "https://registry.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateInvitationFor(ctx, adminID, workspace.ID, RoleMember, 0, "not-an-address"); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatalf("invalid address: %v", err)
	}
	issued, err := service.CreateInvitationFor(ctx, adminID, workspace.ID, RoleAdministrator, 0, "new@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(queue.sent) != 1 {
		t.Fatalf("queued %d emails", len(queue.sent))
	}
	sent := queue.sent[0]
	if sent.key != "invitation:"+issued.ID || sent.message.To != "new@example.com" || sent.message.Data["workspace_name"] != "Mailed" || sent.message.Data["role_label"] != "administrador" || !strings.HasPrefix(sent.message.Data["link"], "https://registry.example/#/invite?token=prinv_") {
		t.Fatalf("unexpected invitation email: %+v", sent)
	}
	parsed, err := url.Parse(sent.message.Data["link"])
	if err != nil {
		t.Fatal(err)
	}
	_, query, _ := strings.Cut(parsed.Fragment, "?")
	values, _ := url.ParseQuery(query)
	if values.Get("token") != issued.Token {
		t.Fatal("emailed link does not carry the invitation token")
	}
	listed, err := service.ListInvitations(ctx, adminID, workspace.ID)
	if err != nil || len(listed) != 1 || listed[0].Email != "new@example.com" {
		t.Fatalf("listing: %+v %v", listed, err)
	}
	if err := service.SetSignupPolicy(ctx, adminID, SignupInvitations); err != nil {
		t.Fatal(err)
	}
	userID, _, err := service.RedeemInvitation(ctx, values.Get("token"), "invited.person", "Invited Person", []byte("synthetic-invited-password-never-reuse"))
	if err != nil {
		t.Fatal(err)
	}
	var address string
	var verified bool
	if err := db.QueryRowContext(ctx, `SELECT email, email_verified FROM registry_users WHERE user_id = ?`, userID).Scan(&address, &verified); err != nil || address != "new@example.com" || !verified {
		t.Fatalf("redeemed account address: %q %v %v", address, verified, err)
	}

	// A link handed over by hand proves nothing about an address.
	plain, err := service.CreateInvitation(ctx, adminID, workspace.ID, RoleMember, 0)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := service.RedeemInvitation(ctx, plain.Token, "plain.person", "Plain Person", []byte("synthetic-invited-password-never-reuse"))
	if err != nil {
		t.Fatal(err)
	}
	var otherAddress sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT email, email_verified FROM registry_users WHERE user_id = ?`, other).Scan(&otherAddress, &verified); err != nil || otherAddress.Valid || verified {
		t.Fatalf("hand-delivered invitation set an address: %v %v %v", otherAddress, verified, err)
	}
}
