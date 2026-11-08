package repositories

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

const personalReadTokenMaxTTL = 30 * 24 * time.Hour

var (
	ErrPersonalTokenUnavailable    = errors.New("personal token is unavailable")
	ErrInvalidPersonalTokenRequest = errors.New("personal token request is invalid")
)

type PersonalReadToken struct {
	ID           string
	WorkspaceID  string
	RepositoryID string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Revoked      bool
}

type IssuedPersonalReadToken struct {
	PersonalReadToken
	Bearer string
}

// IssuePersonalReadToken returns the bearer exactly once, after a transaction
// requiring the person's current reader grant. Callers must not log it.
func (s *Service) IssuePersonalReadToken(ctx context.Context, actorUserID, workspaceID, repositoryID string, ttl time.Duration) (IssuedPersonalReadToken, error) {
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return IssuedPersonalReadToken{}, ErrUnauthenticated
	}
	workspaceID, err = parseUUID(workspaceID, ErrInvalidWorkspaceID)
	if err != nil {
		return IssuedPersonalReadToken{}, ErrInvalidWorkspaceID
	}
	repositoryID, err = parseUUID(repositoryID, ErrInvalidRepositoryID)
	if err != nil {
		return IssuedPersonalReadToken{}, ErrInvalidRepositoryID
	}
	if ttl == 0 {
		ttl = personalReadTokenMaxTTL
	}
	if ttl < time.Minute || ttl > personalReadTokenMaxTTL {
		return IssuedPersonalReadToken{}, ErrInvalidPersonalTokenRequest
	}
	id, err := uuid.NewV7()
	if err != nil {
		return IssuedPersonalReadToken{}, errors.New("personal token identity could not be generated")
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return IssuedPersonalReadToken{}, errors.New("personal token secret could not be generated")
	}
	defer clear(secret[:])
	digest := sha256.Sum256(secret[:])
	now := time.Now().UTC().Truncate(time.Millisecond)
	issued := IssuedPersonalReadToken{
		PersonalReadToken: PersonalReadToken{ID: id.String(), WorkspaceID: workspaceID, RepositoryID: repositoryID, CreatedAt: now, ExpiresAt: now.Add(ttl)},
		Bearer:            "prp_" + id.String() + "." + base64.RawURLEncoding.EncodeToString(secret[:]),
	}
	err = s.WithRepositoryGrantTransaction(ctx, actorID, workspaceID, repositoryID, GrantReader, func(tx *sql.Tx) error {
		query := `SELECT grant_id FROM registry_repository_grants WHERE user_id = ` + bind(s.driver, 1) + ` AND workspace_id = ` + bind(s.driver, 2) + ` AND repository_id = ` + bind(s.driver, 3) + ` AND role = 'reader' AND revoked_at IS NULL`
		var grantID string
		if err := tx.QueryRowContext(ctx, query, actorID, workspaceID, repositoryID).Scan(&grantID); err != nil {
			return errors.New("personal token grant could not be resolved")
		}
		query = `INSERT INTO registry_personal_read_tokens (token_id, user_id, workspace_id, repository_id, reader_grant_id, secret_sha256, created_at_ms, expires_at_ms) VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `, ` + bind(s.driver, 6) + `, ` + bind(s.driver, 7) + `, ` + bind(s.driver, 8) + `)`
		if _, err := tx.ExecContext(ctx, query, issued.ID, actorID, workspaceID, repositoryID, grantID, hex.EncodeToString(digest[:]), now.UnixMilli(), issued.ExpiresAt.UnixMilli()); err != nil {
			return errors.New("personal token could not be created")
		}
		return recordAudit(ctx, tx, s.driver, actorID, "personal_read_token.created", "personal_token", issued.ID)
	})
	if err != nil {
		return IssuedPersonalReadToken{}, err
	}
	return issued, nil
}

// VerifyPersonalReadToken validates the bearer and current authority under the
// same coordination lock used for revocation and grant mutations.
func (s *Service) VerifyPersonalReadToken(ctx context.Context, bearer, workspaceID, repositoryID string) (string, error) {
	var userID string
	err := s.WithPersonalReadTokenTransaction(ctx, bearer, workspaceID, repositoryID, func(_ *sql.Tx, user string) error {
		userID = user
		return nil
	})
	if err != nil {
		return "", err
	}
	return userID, nil
}

// WithPersonalReadTokenTransaction validates the exact token and its original
// grant while holding the authorization coordination lock. The callback may
// read metadata but must not retain the transaction or perform network I/O.
func (s *Service) WithPersonalReadTokenTransaction(ctx context.Context, bearer, workspaceID, repositoryID string, operation func(*sql.Tx, string) error) error {
	if s == nil || s.db == nil || ctx == nil || operation == nil {
		return ErrPersonalTokenUnavailable
	}
	workspaceID, err := parseUUID(workspaceID, ErrPersonalTokenUnavailable)
	if err != nil {
		return ErrPersonalTokenUnavailable
	}
	repositoryID, err = parseUUID(repositoryID, ErrPersonalTokenUnavailable)
	if err != nil {
		return ErrPersonalTokenUnavailable
	}
	if !strings.HasPrefix(bearer, "prp_") {
		return ErrPersonalTokenUnavailable
	}
	idText, encoded, found := strings.Cut(strings.TrimPrefix(bearer, "prp_"), ".")
	id, err := parseUUID(idText, ErrPersonalTokenUnavailable)
	if err != nil || !found || idText != id || len(encoded) != 43 {
		return ErrPersonalTokenUnavailable
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(secret) != 32 {
		return ErrPersonalTokenUnavailable
	}
	defer clear(secret)
	digest := sha256.Sum256(secret)
	var userID string
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		var storedHash, storedWorkspace, storedRepository, grantID string
		var expires int64
		var revoked sql.NullInt64
		query := `SELECT user_id, workspace_id, repository_id, reader_grant_id, secret_sha256, expires_at_ms, revoked_at_ms FROM registry_personal_read_tokens WHERE token_id = ` + bind(s.driver, 1)
		err := tx.QueryRowContext(ctx, query, id).Scan(&userID, &storedWorkspace, &storedRepository, &grantID, &storedHash, &expires, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPersonalTokenUnavailable
		}
		if err != nil {
			return errors.New("personal token could not be checked")
		}
		storedDigest, err := hex.DecodeString(storedHash)
		if err != nil || len(storedDigest) != sha256.Size {
			return errors.New("personal token verifier is invalid")
		}
		if subtle.ConstantTimeCompare(digest[:], storedDigest) != 1 || storedWorkspace != workspaceID || storedRepository != repositoryID || revoked.Valid || time.Now().UTC().UnixMilli() >= expires {
			return ErrPersonalTokenUnavailable
		}
		if err := requireActiveUser(ctx, tx, s.driver, userID); err != nil {
			if errors.Is(err, ErrUserUnavailable) {
				return ErrPersonalTokenUnavailable
			}
			return err
		}
		if _, err := activeWorkspaceRole(ctx, tx, s.driver, workspaceID, userID); err != nil {
			if errors.Is(err, ErrForbidden) {
				return ErrPersonalTokenUnavailable
			}
			return err
		}
		if err := requireActiveRepository(ctx, tx, s.driver, workspaceID, repositoryID); err != nil {
			if errors.Is(err, ErrRepositoryUnavailable) {
				return ErrPersonalTokenUnavailable
			}
			return err
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_repository_grants WHERE user_id = ` + bind(s.driver, 1) + ` AND workspace_id = ` + bind(s.driver, 2) + ` AND repository_id = ` + bind(s.driver, 3) + ` AND grant_id = ` + bind(s.driver, 4) + ` AND role = 'reader' AND revoked_at IS NULL)`
		var granted bool
		if err := tx.QueryRowContext(ctx, query, userID, workspaceID, repositoryID, grantID).Scan(&granted); err != nil {
			return errors.New("personal token authority could not be checked")
		}
		if !granted {
			return ErrPersonalTokenUnavailable
		}
		return operation(tx, userID)
	})
	return err
}

// ListPersonalReadTokens returns only the caller's metadata; revoked and
// expired entries remain visible for recovery and audit, never their verifier.
func (s *Service) ListPersonalReadTokens(ctx context.Context, actorUserID, after string, pageSize int) ([]PersonalReadToken, bool, error) {
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return nil, false, ErrUnauthenticated
	}
	if after != "" {
		after, err = parseUUID(after, ErrInvalidPersonalTokenRequest)
		if err != nil {
			return nil, false, ErrInvalidPersonalTokenRequest
		}
	}
	if pageSize < 1 || pageSize > 100 {
		return nil, false, ErrInvalidPersonalTokenRequest
	}
	tokens := make([]PersonalReadToken, 0, pageSize+1)
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		query := `SELECT token_id, workspace_id, repository_id, created_at_ms, expires_at_ms, revoked_at_ms FROM registry_personal_read_tokens WHERE user_id = ` + bind(s.driver, 1) + ` AND token_id > ` + bind(s.driver, 2) + ` ORDER BY token_id LIMIT ` + bind(s.driver, 3)
		rows, err := tx.QueryContext(ctx, query, actorID, after, pageSize+1)
		if err != nil {
			return errors.New("personal tokens could not be listed")
		}
		defer rows.Close()
		for rows.Next() {
			var token PersonalReadToken
			var created, expires int64
			var revoked sql.NullInt64
			if err := rows.Scan(&token.ID, &token.WorkspaceID, &token.RepositoryID, &created, &expires, &revoked); err != nil {
				return errors.New("personal token metadata could not be read")
			}
			token.CreatedAt = time.UnixMilli(created).UTC()
			token.ExpiresAt = time.UnixMilli(expires).UTC()
			token.Revoked = revoked.Valid
			tokens = append(tokens, token)
		}
		if err := rows.Err(); err != nil {
			return errors.New("personal tokens could not be iterated")
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	hasMore := len(tokens) > pageSize
	if hasMore {
		tokens = tokens[:pageSize]
	}
	return tokens, hasMore, nil
}

// RevokePersonalReadToken is idempotent for a token owned by the caller and
// remains available after a repository grant is revoked.
func (s *Service) RevokePersonalReadToken(ctx context.Context, actorUserID, tokenID string) error {
	actorID, err := parseUUID(actorUserID, ErrUnauthenticated)
	if err != nil {
		return ErrUnauthenticated
	}
	tokenID, err = parseUUID(tokenID, ErrPersonalTokenUnavailable)
	if err != nil {
		return ErrPersonalTokenUnavailable
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actorID); err != nil {
			return err
		}
		query := `UPDATE registry_personal_read_tokens SET revoked_at_ms = ` + bind(s.driver, 1) + ` WHERE token_id = ` + bind(s.driver, 2) + ` AND user_id = ` + bind(s.driver, 3) + ` AND revoked_at_ms IS NULL`
		result, err := tx.ExecContext(ctx, query, time.Now().UTC().UnixMilli(), tokenID, actorID)
		if err != nil {
			return errors.New("personal token could not be revoked")
		}
		count, err := result.RowsAffected()
		if err != nil {
			return errors.New("personal token revocation could not be checked")
		}
		if count == 1 {
			return recordAudit(ctx, tx, s.driver, actorID, "personal_read_token.revoked", "personal_token", tokenID)
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_personal_read_tokens WHERE token_id = ` + bind(s.driver, 1) + ` AND user_id = ` + bind(s.driver, 2) + `)`
		var exists bool
		if err := tx.QueryRowContext(ctx, query, tokenID, actorID).Scan(&exists); err != nil {
			return errors.New("personal token ownership could not be checked")
		}
		if !exists {
			return ErrPersonalTokenUnavailable
		}
		return nil
	})
}
