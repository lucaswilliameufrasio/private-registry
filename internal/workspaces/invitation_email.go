package workspaces

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strings"

	"private-registry/internal/config"
	"private-registry/internal/email"
)

type invitationMailer struct {
	queue  email.Enqueuer
	origin string
}

// EnableEmail lets invitations be delivered by email. origin is the
// registry's canonical origin; the link opens its web interface.
func (s *Service) EnableEmail(queue email.Enqueuer, origin string) error {
	parsed, err := url.Parse(origin)
	if s == nil || queue == nil || err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return errors.New("invitation email could not be enabled")
	}
	s.mail = &invitationMailer{queue: queue, origin: strings.TrimSuffix(origin, "/")}
	return nil
}

func (m *invitationMailer) send(ctx context.Context, tx *sql.Tx, driver config.DatabaseDriver, issued IssuedInvitation, workspaceID, inviterID, address string) error {
	var workspaceName, inviterName string
	if err := tx.QueryRowContext(ctx, `SELECT display_name FROM registry_workspaces WHERE workspace_id = `+bind(driver, 1), workspaceID).Scan(&workspaceName); err != nil {
		return errors.New("invitation workspace could not be read")
	}
	if err := tx.QueryRowContext(ctx, `SELECT display_name FROM registry_users WHERE user_id = `+bind(driver, 1), inviterID).Scan(&inviterName); err != nil {
		return errors.New("invitation sender could not be read")
	}
	role := "membro"
	if issued.Role == RoleAdministrator {
		role = "administrador"
	}
	message := email.Message{Template: email.TemplateInvitation, To: address, Data: map[string]string{
		"workspace_name": workspaceName,
		"inviter_name":   inviterName,
		"role_label":     role,
		"link":           m.origin + "/#/invite?token=" + url.QueryEscape(issued.Token),
		"expires_at":     issued.ExpiresAt.UTC().Format("2006-01-02 15:04"),
	}}
	if err := m.queue.EnqueueTx(ctx, tx, "invitation:"+issued.ID, message); err != nil {
		if errors.Is(err, email.ErrInvalidMessage) {
			return ErrInvalidInvitation
		}
		return errors.New("invitation email could not be queued")
	}
	return nil
}
