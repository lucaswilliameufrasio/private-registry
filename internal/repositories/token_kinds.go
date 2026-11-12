package repositories

import (
	"context"
	"errors"
	"time"
)

// TokenKind names one family of repository tokens.
type TokenKind string

const (
	TokenRead       TokenKind = "read"
	TokenCargoWrite TokenKind = "cargo-write"
	TokenNPMWrite   TokenKind = "npm-write"
	TokenPubWrite   TokenKind = "pub-write"
	TokenOCIWrite   TokenKind = "oci-write"
)

var ErrInvalidTokenKind = errors.New("token kind is invalid")

// WriteTokenKindFor returns the write token family of a repository format.
func WriteTokenKindFor(format Format) (TokenKind, bool) {
	switch format {
	case FormatCargo:
		return TokenCargoWrite, true
	case FormatNPM:
		return TokenNPMWrite, true
	case FormatPub:
		return TokenPubWrite, true
	case FormatOCI:
		return TokenOCIWrite, true
	}
	return "", false
}

// IssuedToken is the common view of a newly issued token.
type IssuedToken struct {
	ID        string
	Kind      TokenKind
	CreatedAt time.Time
	ExpiresAt time.Time
	Bearer    string
}

// TokenMetadata is the common view of a stored token; it never carries the
// bearer.
type TokenMetadata struct {
	ID           string
	Kind         TokenKind
	WorkspaceID  string
	RepositoryID string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Revoked      bool
}

// IssueToken issues a token of kind owned by owner. Authorization of owner
// is enforced by the kind's own issuer: the current grant must allow it.
func (s *Service) IssueToken(ctx context.Context, owner, workspace, repository string, kind TokenKind, ttl time.Duration) (IssuedToken, error) {
	switch kind {
	case TokenRead:
		token, err := s.IssuePersonalReadToken(ctx, owner, workspace, repository, ttl)
		return IssuedToken{ID: token.ID, Kind: kind, CreatedAt: token.CreatedAt, ExpiresAt: token.ExpiresAt, Bearer: token.Bearer}, err
	case TokenCargoWrite:
		token, err := s.IssueCargoWriteToken(ctx, owner, workspace, repository, ttl)
		return IssuedToken{ID: token.ID, Kind: kind, CreatedAt: token.CreatedAt, ExpiresAt: token.ExpiresAt, Bearer: token.Bearer}, err
	case TokenNPMWrite:
		token, err := s.IssueNPMWriteToken(ctx, owner, workspace, repository, ttl)
		return IssuedToken{ID: token.ID, Kind: kind, CreatedAt: token.CreatedAt, ExpiresAt: token.ExpiresAt, Bearer: token.Bearer}, err
	case TokenPubWrite:
		token, err := s.IssuePubWriteToken(ctx, owner, workspace, repository, ttl)
		return IssuedToken{ID: token.ID, Kind: kind, CreatedAt: token.CreatedAt, ExpiresAt: token.ExpiresAt, Bearer: token.Bearer}, err
	case TokenOCIWrite:
		token, err := s.IssueOCIWriteToken(ctx, owner, workspace, repository, ttl)
		return IssuedToken{ID: token.ID, Kind: kind, CreatedAt: token.CreatedAt, ExpiresAt: token.ExpiresAt, Bearer: token.Bearer}, err
	}
	return IssuedToken{}, ErrInvalidTokenKind
}

// ListTokens returns every token of owner across all kinds, up to 500 each.
func (s *Service) ListTokens(ctx context.Context, owner string) ([]TokenMetadata, error) {
	var items []TokenMetadata
	add := func(kind TokenKind, id, workspace, repository string, created, expires time.Time, revoked bool) {
		items = append(items, TokenMetadata{ID: id, Kind: kind, WorkspaceID: workspace, RepositoryID: repository, CreatedAt: created, ExpiresAt: expires, Revoked: revoked})
	}
	read, _, err := s.ListPersonalReadTokens(ctx, owner, "", 100)
	if err != nil {
		return nil, err
	}
	for _, token := range read {
		add(TokenRead, token.ID, token.WorkspaceID, token.RepositoryID, token.CreatedAt, token.ExpiresAt, token.Revoked)
	}
	cargo, _, err := s.ListCargoWriteTokens(ctx, owner, "", 100)
	if err != nil {
		return nil, err
	}
	for _, token := range cargo {
		add(TokenCargoWrite, token.ID, token.WorkspaceID, token.RepositoryID, token.CreatedAt, token.ExpiresAt, token.Revoked)
	}
	npmTokens, _, err := s.ListNPMWriteTokens(ctx, owner, "", 100)
	if err != nil {
		return nil, err
	}
	for _, token := range npmTokens {
		add(TokenNPMWrite, token.ID, token.WorkspaceID, token.RepositoryID, token.CreatedAt, token.ExpiresAt, token.Revoked)
	}
	pubTokens, _, err := s.ListPubWriteTokens(ctx, owner, "", 100)
	if err != nil {
		return nil, err
	}
	for _, token := range pubTokens {
		add(TokenPubWrite, token.ID, token.WorkspaceID, token.RepositoryID, token.CreatedAt, token.ExpiresAt, token.Revoked)
	}
	ociTokens, _, err := s.ListOCIWriteTokens(ctx, owner, "", 100)
	if err != nil {
		return nil, err
	}
	for _, token := range ociTokens {
		add(TokenOCIWrite, token.ID, token.WorkspaceID, token.RepositoryID, token.CreatedAt, token.ExpiresAt, token.Revoked)
	}
	return items, nil
}

// RevokeToken revokes one token of owner.
func (s *Service) RevokeToken(ctx context.Context, owner string, kind TokenKind, tokenID string) error {
	switch kind {
	case TokenRead:
		return s.RevokePersonalReadToken(ctx, owner, tokenID)
	case TokenCargoWrite:
		return s.RevokeCargoWriteToken(ctx, owner, tokenID)
	case TokenNPMWrite:
		return s.RevokeNPMWriteToken(ctx, owner, tokenID)
	case TokenPubWrite:
		return s.RevokePubWriteToken(ctx, owner, tokenID)
	case TokenOCIWrite:
		return s.RevokeOCIWriteToken(ctx, owner, tokenID)
	}
	return ErrInvalidTokenKind
}

// RepositoryFormat returns the format of an active repository.
func (s *Service) RepositoryFormat(ctx context.Context, workspace, repository string) (Format, error) {
	var format string
	err := s.db.QueryRowContext(ctx, `SELECT format FROM registry_repositories WHERE workspace_id = `+bind(s.driver, 1)+` AND repository_id = `+bind(s.driver, 2)+` AND status = 'active'`, workspace, repository).Scan(&format)
	if err != nil {
		return "", ErrRepositoryUnavailable
	}
	return Format(format), nil
}
