package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/google/uuid"
)

// resolveMuiraIdentity resolves only an existing explicit link. The caller must
// first verify the issuer, token signature, audience, expiry and nonce. This
// function does not authenticate a request, create a session or grant access.
func (s *Service) resolveMuiraIdentity(ctx context.Context, issuer, subject string) (string, error) {
	if s == nil || s.db == nil || ctx == nil {
		return "", ErrUnavailable
	}
	id, err := uuid.Parse(subject)
	if err != nil || id == uuid.Nil || id.Version() != 7 || id.String() != subject || issuer == "" || len(issuer) > 2048 || strings.TrimSpace(issuer) != issuer {
		return "", ErrRejected
	}
	query := `SELECT u.user_id FROM registry_external_identities i JOIN registry_users u ON u.user_id = i.user_id WHERE i.provider_id = 'muira' AND i.issuer = ` + bind(s.driver, 1) + ` AND i.subject = ` + bind(s.driver, 2) + ` AND u.status = 'active'`
	var userID string
	if err := s.db.QueryRowContext(ctx, query, issuer, subject).Scan(&userID); errors.Is(err, sql.ErrNoRows) {
		return "", ErrRejected
	} else if err != nil {
		return "", ErrUnavailable
	}
	user, err := uuid.Parse(userID)
	if err != nil || user == uuid.Nil || user.String() != userID {
		return "", ErrUnavailable
	}
	return userID, nil
}
