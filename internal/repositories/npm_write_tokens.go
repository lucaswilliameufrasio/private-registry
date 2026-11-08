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

var ErrNPMWriteTokenUnavailable = errors.New("npm write credential is unavailable")

type IssuedNPMWriteToken struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	Bearer    string
}

type NPMWriteTokenMetadata struct {
	ID           string
	WorkspaceID  string
	RepositoryID string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Revoked      bool
}

// IssueNPMWriteToken issues a publisher capability tied to the current grant.
// A future HTTP caller must enforce recent MFA and CSRF. It does not authorize
// dist-tag movement or removal. The bearer must not be logged or retained.
func (s *Service) IssueNPMWriteToken(ctx context.Context, actor, workspace, repository string, ttl time.Duration) (IssuedNPMWriteToken, error) {
	if s == nil || s.db == nil || ctx == nil {
		return IssuedNPMWriteToken{}, ErrNPMWriteTokenUnavailable
	}
	actor, err := parseUUID(actor, ErrUnauthenticated)
	if err != nil {
		return IssuedNPMWriteToken{}, err
	}
	workspace, err = parseUUID(workspace, ErrInvalidWorkspaceID)
	if err != nil {
		return IssuedNPMWriteToken{}, err
	}
	repository, err = parseUUID(repository, ErrInvalidRepositoryID)
	if err != nil {
		return IssuedNPMWriteToken{}, err
	}
	if ttl == 0 {
		ttl = 30 * 24 * time.Hour
	}
	if ttl < time.Minute || ttl > 30*24*time.Hour {
		return IssuedNPMWriteToken{}, ErrInvalidPersonalTokenRequest
	}
	id, err := uuid.NewV7()
	if err != nil {
		return IssuedNPMWriteToken{}, errors.New("npm write credential identity could not be created")
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return IssuedNPMWriteToken{}, errors.New("npm write credential secret could not be created")
	}
	defer clear(secret[:])
	digest := sha256.Sum256(secret[:])
	now := time.Now().UTC().Truncate(time.Millisecond)
	issued := IssuedNPMWriteToken{ID: id.String(), CreatedAt: now, ExpiresAt: now.Add(ttl), Bearer: "prnw_" + id.String() + "." + base64.RawURLEncoding.EncodeToString(secret[:])}
	err = s.WithRepositoryGrantTransaction(ctx, actor, workspace, repository, GrantPublisher, func(tx *sql.Tx) error {
		query := `SELECT grant_id FROM registry_repository_grants WHERE user_id = ` + bind(s.driver, 1) + ` AND workspace_id = ` + bind(s.driver, 2) + ` AND repository_id = ` + bind(s.driver, 3) + ` AND role = 'publisher' AND revoked_at IS NULL`
		var grant string
		if err := tx.QueryRowContext(ctx, query, actor, workspace, repository).Scan(&grant); err != nil {
			return errors.New("npm publisher grant could not be resolved")
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_repositories WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND status = 'active' AND format = 'npm')`
		var allowed bool
		if err := tx.QueryRowContext(ctx, query, workspace, repository).Scan(&allowed); err != nil {
			return errors.New("npm repository format could not be checked")
		}
		if !allowed {
			return ErrNPMWriteTokenUnavailable
		}
		query = `INSERT INTO registry_npm_write_tokens (token_id, user_id, workspace_id, repository_id, publisher_grant_id, secret_sha256, created_at_ms, expires_at_ms) VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `, ` + bind(s.driver, 6) + `, ` + bind(s.driver, 7) + `, ` + bind(s.driver, 8) + `)`
		if _, err := tx.ExecContext(ctx, query, issued.ID, actor, workspace, repository, grant, hex.EncodeToString(digest[:]), now.UnixMilli(), issued.ExpiresAt.UnixMilli()); err != nil {
			return errors.New("npm write credential could not be created")
		}
		return recordAudit(ctx, tx, s.driver, actor, "npm_write_token.created", "npm_write_token", issued.ID)
	})
	if err != nil {
		return IssuedNPMWriteToken{}, err
	}
	return issued, nil
}

// WithNPMWriteTokenTransaction validates the capability and current grant in
// the same coordinated transaction. The callback must not perform network I/O.
// It is not sufficient authorization for dist-tag movement or removal.
func (s *Service) WithNPMWriteTokenTransaction(ctx context.Context, bearer, workspace, repository string, apply func(*sql.Tx, string) error) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrNPMWriteTokenUnavailable
	}
	workspace, err := parseUUID(workspace, ErrNPMWriteTokenUnavailable)
	if err != nil {
		return ErrNPMWriteTokenUnavailable
	}
	repository, err = parseUUID(repository, ErrNPMWriteTokenUnavailable)
	if err != nil || apply == nil || !strings.HasPrefix(bearer, "prnw_") {
		return ErrNPMWriteTokenUnavailable
	}
	idText, encoded, found := strings.Cut(strings.TrimPrefix(bearer, "prnw_"), ".")
	id, err := parseUUID(idText, ErrNPMWriteTokenUnavailable)
	if err != nil || !found || idText != id || len(encoded) != 43 {
		return ErrNPMWriteTokenUnavailable
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(secret) != 32 {
		return ErrNPMWriteTokenUnavailable
	}
	defer clear(secret)
	digest := sha256.Sum256(secret)
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		query := `SELECT user_id, workspace_id, repository_id, publisher_grant_id, secret_sha256, expires_at_ms, revoked_at_ms FROM registry_npm_write_tokens WHERE token_id = ` + bind(s.driver, 1)
		var user, storedWorkspace, storedRepository, grant, storedHash string
		var expires int64
		var revoked sql.NullInt64
		if err := tx.QueryRowContext(ctx, query, id).Scan(&user, &storedWorkspace, &storedRepository, &grant, &storedHash, &expires, &revoked); errors.Is(err, sql.ErrNoRows) {
			return ErrNPMWriteTokenUnavailable
		} else if err != nil {
			return errors.New("npm write credential could not be checked")
		}
		storedDigest, err := hex.DecodeString(storedHash)
		if err != nil || len(storedDigest) != sha256.Size {
			return errors.New("npm write credential verifier is invalid")
		}
		if subtle.ConstantTimeCompare(digest[:], storedDigest) != 1 || storedWorkspace != workspace || storedRepository != repository || revoked.Valid || time.Now().UTC().UnixMilli() >= expires {
			return ErrNPMWriteTokenUnavailable
		}
		if err := requireActiveUser(ctx, tx, s.driver, user); err != nil {
			if errors.Is(err, ErrUserUnavailable) {
				return ErrNPMWriteTokenUnavailable
			}
			return err
		}
		if _, err := activeWorkspaceRole(ctx, tx, s.driver, workspace, user); err != nil {
			if errors.Is(err, ErrForbidden) {
				return ErrNPMWriteTokenUnavailable
			}
			return err
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_repositories WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND status = 'active' AND format = 'npm')`
		var allowed bool
		if err := tx.QueryRowContext(ctx, query, workspace, repository).Scan(&allowed); err != nil {
			return errors.New("npm repository could not be checked")
		}
		if !allowed {
			return ErrNPMWriteTokenUnavailable
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_repository_grants WHERE user_id = ` + bind(s.driver, 1) + ` AND workspace_id = ` + bind(s.driver, 2) + ` AND repository_id = ` + bind(s.driver, 3) + ` AND grant_id = ` + bind(s.driver, 4) + ` AND role = 'publisher' AND revoked_at IS NULL)`
		if err := tx.QueryRowContext(ctx, query, user, workspace, repository, grant).Scan(&allowed); err != nil {
			return errors.New("npm publisher authority could not be checked")
		}
		if !allowed {
			return ErrNPMWriteTokenUnavailable
		}
		return apply(tx, user)
	})
}

// RevokeNPMWriteToken is owner-only, idempotent and remains available after a
// publisher grant is removed. The first revocation is audited transactionally.
func (s *Service) RevokeNPMWriteToken(ctx context.Context, actor, tokenID string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrNPMWriteTokenUnavailable
	}
	actor, err := parseUUID(actor, ErrUnauthenticated)
	if err != nil {
		return err
	}
	tokenID, err = parseUUID(tokenID, ErrNPMWriteTokenUnavailable)
	if err != nil {
		return ErrNPMWriteTokenUnavailable
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actor); err != nil {
			return err
		}
		query := `SELECT revoked_at_ms FROM registry_npm_write_tokens WHERE token_id = ` + bind(s.driver, 1) + ` AND user_id = ` + bind(s.driver, 2)
		var revoked sql.NullInt64
		if err := tx.QueryRowContext(ctx, query, tokenID, actor).Scan(&revoked); errors.Is(err, sql.ErrNoRows) {
			return ErrNPMWriteTokenUnavailable
		} else if err != nil {
			return errors.New("npm write credential could not be checked")
		}
		if revoked.Valid {
			return nil
		}
		query = `UPDATE registry_npm_write_tokens SET revoked_at_ms = ` + bind(s.driver, 1) + ` WHERE token_id = ` + bind(s.driver, 2) + ` AND user_id = ` + bind(s.driver, 3) + ` AND revoked_at_ms IS NULL`
		if _, err := tx.ExecContext(ctx, query, time.Now().UTC().UnixMilli(), tokenID, actor); err != nil {
			return errors.New("npm write credential could not be revoked")
		}
		return recordAudit(ctx, tx, s.driver, actor, "npm_write_token.revoked", "npm_write_token", tokenID)
	})
}

// ListNPMWriteTokens returns only the owner's metadata, including expired and
// revoked credentials; it never returns bearer values or their verifiers.
func (s *Service) ListNPMWriteTokens(ctx context.Context, actor, after string, pageSize int) ([]NPMWriteTokenMetadata, bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, false, ErrNPMWriteTokenUnavailable
	}
	actor, err := parseUUID(actor, ErrUnauthenticated)
	if err != nil {
		return nil, false, err
	}
	if after != "" {
		after, err = parseUUID(after, ErrInvalidPersonalTokenRequest)
		if err != nil {
			return nil, false, err
		}
	}
	if pageSize < 1 || pageSize > 100 {
		return nil, false, ErrInvalidPersonalTokenRequest
	}
	items := make([]NPMWriteTokenMetadata, 0, pageSize+1)
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actor); err != nil {
			return err
		}
		query := `SELECT token_id, workspace_id, repository_id, created_at_ms, expires_at_ms, revoked_at_ms FROM registry_npm_write_tokens WHERE user_id = ` + bind(s.driver, 1) + ` AND token_id > ` + bind(s.driver, 2) + ` ORDER BY token_id LIMIT ` + bind(s.driver, 3)
		rows, err := tx.QueryContext(ctx, query, actor, after, pageSize+1)
		if err != nil {
			return errors.New("npm write credential metadata could not be listed")
		}
		defer rows.Close()
		for rows.Next() {
			var item NPMWriteTokenMetadata
			var created, expires int64
			var revoked sql.NullInt64
			if err := rows.Scan(&item.ID, &item.WorkspaceID, &item.RepositoryID, &created, &expires, &revoked); err != nil {
				return errors.New("npm write credential metadata could not be read")
			}
			item.CreatedAt = time.UnixMilli(created).UTC()
			item.ExpiresAt = time.UnixMilli(expires).UTC()
			item.Revoked = revoked.Valid
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return errors.New("npm write credential metadata could not be iterated")
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	more := len(items) > pageSize
	if more {
		items = items[:pageSize]
	}
	return items, more, nil
}
