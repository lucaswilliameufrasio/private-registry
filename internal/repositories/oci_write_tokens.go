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

var ErrOCIWriteTokenUnavailable = errors.New("OCI write credential is unavailable")

type IssuedOCIWriteToken struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	Bearer    string
}

type OCIWriteTokenMetadata struct {
	ID           string
	WorkspaceID  string
	RepositoryID string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Revoked      bool
}

// IssueOCIWriteToken issues a publisher capability tied to the current grant.
// A future HTTP caller must enforce recent MFA and CSRF. It does not authorize
// package withdrawal or removal. The bearer must not be logged or retained.
func (s *Service) IssueOCIWriteToken(ctx context.Context, actor, workspace, repository string, ttl time.Duration) (IssuedOCIWriteToken, error) {
	if s == nil || s.db == nil || ctx == nil {
		return IssuedOCIWriteToken{}, ErrOCIWriteTokenUnavailable
	}
	actor, err := parseUUID(actor, ErrUnauthenticated)
	if err != nil {
		return IssuedOCIWriteToken{}, err
	}
	workspace, err = parseUUID(workspace, ErrInvalidWorkspaceID)
	if err != nil {
		return IssuedOCIWriteToken{}, err
	}
	repository, err = parseUUID(repository, ErrInvalidRepositoryID)
	if err != nil {
		return IssuedOCIWriteToken{}, err
	}
	if ttl == 0 {
		ttl = 30 * 24 * time.Hour
	}
	if ttl < time.Minute || ttl > 30*24*time.Hour {
		return IssuedOCIWriteToken{}, ErrInvalidPersonalTokenRequest
	}
	id, err := uuid.NewV7()
	if err != nil {
		return IssuedOCIWriteToken{}, errors.New("OCI write credential identity could not be created")
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return IssuedOCIWriteToken{}, errors.New("OCI write credential secret could not be created")
	}
	defer clear(secret[:])
	digest := sha256.Sum256(secret[:])
	now := time.Now().UTC().Truncate(time.Millisecond)
	issued := IssuedOCIWriteToken{ID: id.String(), CreatedAt: now, ExpiresAt: now.Add(ttl), Bearer: "prow_" + id.String() + "." + base64.RawURLEncoding.EncodeToString(secret[:])}
	err = s.WithRepositoryGrantTransaction(ctx, actor, workspace, repository, GrantPublisher, func(tx *sql.Tx) error {
		query := `SELECT grant_id FROM registry_repository_grants WHERE user_id = ` + bind(s.driver, 1) + ` AND workspace_id = ` + bind(s.driver, 2) + ` AND repository_id = ` + bind(s.driver, 3) + ` AND role = 'publisher' AND revoked_at IS NULL`
		var grant string
		if err := tx.QueryRowContext(ctx, query, actor, workspace, repository).Scan(&grant); err != nil {
			return errors.New("OCI publisher grant could not be resolved")
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_repositories WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND status = 'active' AND format = 'oci')`
		var allowed bool
		if err := tx.QueryRowContext(ctx, query, workspace, repository).Scan(&allowed); err != nil {
			return errors.New("OCI repository format could not be checked")
		}
		if !allowed {
			return ErrOCIWriteTokenUnavailable
		}
		query = `SELECT grant_id FROM registry_repository_grants WHERE user_id = ` + bind(s.driver, 1) + ` AND workspace_id = ` + bind(s.driver, 2) + ` AND repository_id = ` + bind(s.driver, 3) + ` AND role = 'reader' AND revoked_at IS NULL`
		var readerGrant sql.NullString
		if err := tx.QueryRowContext(ctx, query, actor, workspace, repository).Scan(&readerGrant); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return errors.New("OCI reader grant could not be resolved")
		}
		query = `INSERT INTO registry_oci_write_tokens (token_id, user_id, workspace_id, repository_id, publisher_grant_id, reader_grant_id, secret_sha256, created_at_ms, expires_at_ms) VALUES (` + bind(s.driver, 1) + `, ` + bind(s.driver, 2) + `, ` + bind(s.driver, 3) + `, ` + bind(s.driver, 4) + `, ` + bind(s.driver, 5) + `, ` + bind(s.driver, 6) + `, ` + bind(s.driver, 7) + `, ` + bind(s.driver, 8) + `, ` + bind(s.driver, 9) + `)`
		if _, err := tx.ExecContext(ctx, query, issued.ID, actor, workspace, repository, grant, readerGrant, hex.EncodeToString(digest[:]), now.UnixMilli(), issued.ExpiresAt.UnixMilli()); err != nil {
			return errors.New("OCI write credential could not be created")
		}
		return recordAudit(ctx, tx, s.driver, actor, "oci_write_token.created", "oci_write_token", issued.ID)
	})
	if err != nil {
		return IssuedOCIWriteToken{}, err
	}
	return issued, nil
}

// WithOCIWriteTokenTransaction validates the capability and current grant in
// the same coordinated transaction. The callback must not perform network I/O.
// It is not sufficient authorization for package withdrawal or removal.
func (s *Service) WithOCIWriteTokenTransaction(ctx context.Context, bearer, workspace, repository string, apply func(*sql.Tx, string) error) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrOCIWriteTokenUnavailable
	}
	workspace, err := parseUUID(workspace, ErrOCIWriteTokenUnavailable)
	if err != nil {
		return ErrOCIWriteTokenUnavailable
	}
	repository, err = parseUUID(repository, ErrOCIWriteTokenUnavailable)
	if err != nil || apply == nil || !strings.HasPrefix(bearer, "prow_") {
		return ErrOCIWriteTokenUnavailable
	}
	idText, encoded, found := strings.Cut(strings.TrimPrefix(bearer, "prow_"), ".")
	id, err := parseUUID(idText, ErrOCIWriteTokenUnavailable)
	if err != nil || !found || idText != id || len(encoded) != 43 {
		return ErrOCIWriteTokenUnavailable
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(secret) != 32 {
		return ErrOCIWriteTokenUnavailable
	}
	defer clear(secret)
	digest := sha256.Sum256(secret)
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		query := `SELECT user_id, workspace_id, repository_id, publisher_grant_id, secret_sha256, expires_at_ms, revoked_at_ms FROM registry_oci_write_tokens WHERE token_id = ` + bind(s.driver, 1)
		var user, storedWorkspace, storedRepository, grant, storedHash string
		var expires int64
		var revoked sql.NullInt64
		if err := tx.QueryRowContext(ctx, query, id).Scan(&user, &storedWorkspace, &storedRepository, &grant, &storedHash, &expires, &revoked); errors.Is(err, sql.ErrNoRows) {
			return ErrOCIWriteTokenUnavailable
		} else if err != nil {
			return errors.New("OCI write credential could not be checked")
		}
		storedDigest, err := hex.DecodeString(storedHash)
		if err != nil || len(storedDigest) != sha256.Size {
			return errors.New("OCI write credential verifier is invalid")
		}
		if subtle.ConstantTimeCompare(digest[:], storedDigest) != 1 || storedWorkspace != workspace || storedRepository != repository || revoked.Valid || time.Now().UTC().UnixMilli() >= expires {
			return ErrOCIWriteTokenUnavailable
		}
		if err := requireActiveUser(ctx, tx, s.driver, user); err != nil {
			if errors.Is(err, ErrUserUnavailable) {
				return ErrOCIWriteTokenUnavailable
			}
			return err
		}
		if _, err := activeWorkspaceRole(ctx, tx, s.driver, workspace, user); err != nil {
			if errors.Is(err, ErrForbidden) {
				return ErrOCIWriteTokenUnavailable
			}
			return err
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_repositories WHERE workspace_id = ` + bind(s.driver, 1) + ` AND repository_id = ` + bind(s.driver, 2) + ` AND status = 'active' AND format = 'oci')`
		var allowed bool
		if err := tx.QueryRowContext(ctx, query, workspace, repository).Scan(&allowed); err != nil {
			return errors.New("OCI repository could not be checked")
		}
		if !allowed {
			return ErrOCIWriteTokenUnavailable
		}
		query = `SELECT EXISTS (SELECT 1 FROM registry_repository_grants WHERE user_id = ` + bind(s.driver, 1) + ` AND workspace_id = ` + bind(s.driver, 2) + ` AND repository_id = ` + bind(s.driver, 3) + ` AND grant_id = ` + bind(s.driver, 4) + ` AND role = 'publisher' AND revoked_at IS NULL)`
		if err := tx.QueryRowContext(ctx, query, user, workspace, repository, grant).Scan(&allowed); err != nil {
			return errors.New("OCI publisher authority could not be checked")
		}
		if !allowed {
			return ErrOCIWriteTokenUnavailable
		}
		return apply(tx, user)
	})
}

// RevokeOCIWriteToken is owner-only, idempotent and remains available after a
// publisher grant is removed. The first revocation is audited transactionally.
func (s *Service) RevokeOCIWriteToken(ctx context.Context, actor, tokenID string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrOCIWriteTokenUnavailable
	}
	actor, err := parseUUID(actor, ErrUnauthenticated)
	if err != nil {
		return err
	}
	tokenID, err = parseUUID(tokenID, ErrOCIWriteTokenUnavailable)
	if err != nil {
		return ErrOCIWriteTokenUnavailable
	}
	return s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actor); err != nil {
			return err
		}
		query := `SELECT revoked_at_ms FROM registry_oci_write_tokens WHERE token_id = ` + bind(s.driver, 1) + ` AND user_id = ` + bind(s.driver, 2)
		var revoked sql.NullInt64
		if err := tx.QueryRowContext(ctx, query, tokenID, actor).Scan(&revoked); errors.Is(err, sql.ErrNoRows) {
			return ErrOCIWriteTokenUnavailable
		} else if err != nil {
			return errors.New("OCI write credential could not be checked")
		}
		if revoked.Valid {
			return nil
		}
		query = `UPDATE registry_oci_write_tokens SET revoked_at_ms = ` + bind(s.driver, 1) + ` WHERE token_id = ` + bind(s.driver, 2) + ` AND user_id = ` + bind(s.driver, 3) + ` AND revoked_at_ms IS NULL`
		if _, err := tx.ExecContext(ctx, query, time.Now().UTC().UnixMilli(), tokenID, actor); err != nil {
			return errors.New("OCI write credential could not be revoked")
		}
		return recordAudit(ctx, tx, s.driver, actor, "oci_write_token.revoked", "oci_write_token", tokenID)
	})
}

// ListOCIWriteTokens returns only the owner's metadata, including expired and
// revoked credentials; it never returns bearer values or their verifiers.
func (s *Service) ListOCIWriteTokens(ctx context.Context, actor, after string, pageSize int) ([]OCIWriteTokenMetadata, bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, false, ErrOCIWriteTokenUnavailable
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
	items := make([]OCIWriteTokenMetadata, 0, pageSize+1)
	err = s.withWriteTransaction(ctx, func(tx *sql.Tx) error {
		if err := requireActiveUser(ctx, tx, s.driver, actor); err != nil {
			return err
		}
		query := `SELECT token_id, workspace_id, repository_id, created_at_ms, expires_at_ms, revoked_at_ms FROM registry_oci_write_tokens WHERE user_id = ` + bind(s.driver, 1) + ` AND token_id > ` + bind(s.driver, 2) + ` ORDER BY token_id LIMIT ` + bind(s.driver, 3)
		rows, err := tx.QueryContext(ctx, query, actor, after, pageSize+1)
		if err != nil {
			return errors.New("OCI write credential metadata could not be listed")
		}
		defer rows.Close()
		for rows.Next() {
			var item OCIWriteTokenMetadata
			var created, expires int64
			var revoked sql.NullInt64
			if err := rows.Scan(&item.ID, &item.WorkspaceID, &item.RepositoryID, &created, &expires, &revoked); err != nil {
				return errors.New("OCI write credential metadata could not be read")
			}
			item.CreatedAt = time.UnixMilli(created).UTC()
			item.ExpiresAt = time.UnixMilli(expires).UTC()
			item.Revoked = revoked.Valid
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return errors.New("OCI write credential metadata could not be iterated")
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
