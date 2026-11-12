// Package trustedpub exchanges a GitHub Actions OIDC identity token for
// short-lived registry tokens of a service account, so CI publishes without a
// stored secret. A repository manager declares which GitHub repository, ref
// and optional environment may act as which service account.
package trustedpub

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"private-registry/internal/config"
	"private-registry/internal/repositories"
)

const (
	GitHubIssuer = "https://token.actions.githubusercontent.com"
	TokenTTL     = 15 * time.Minute
	maxRawToken  = 16 << 10
)

var (
	ErrRejected        = errors.New("CI identity token was rejected")
	ErrNoPublisher     = errors.New("no trusted publisher matches this CI identity")
	ErrReplay          = errors.New("CI identity token was already exchanged")
	ErrInvalidPolicy   = errors.New("trusted publisher definition is invalid")
	ErrUnknown         = errors.New("trusted publisher is unknown")
	ErrUnavailable     = errors.New("trusted publishing is temporarily unavailable")
	ErrNotServiceAcct  = errors.New("trusted publishers can only act as an active service account of the workspace")
	githubRepository   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)
	githubRefPattern   = regexp.MustCompile(`^refs/(heads|tags)/[A-Za-z0-9._/-]{1,200}\*?$`)
	environmentPattern = regexp.MustCompile(`^[A-Za-z0-9._ -]{1,255}$`)
)

type Publisher struct {
	ID               string
	ServiceAccountID string
	Repository       string
	RepositoryID     string
	Ref              string
	Environment      string
	CreatedBy        string
	CreatedAt        time.Time
}

type Exchanged struct {
	Write repositories.IssuedToken
	// Read is empty when the service account has no reader grant.
	Read      repositories.IssuedToken
	Publisher string
}

type Service struct {
	db       *sql.DB
	driver   config.DatabaseDriver
	repos    *repositories.Service
	issuer   string
	audience string
	client   *http.Client

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
}

// New prepares the exchange. Discovery runs on first use, so an unreachable
// GitHub does not stop the registry from starting.
func New(db *sql.DB, driver config.DatabaseDriver, repos *repositories.Service, issuer, audience string, client *http.Client) (*Service, error) {
	if db == nil || repos == nil || client == nil || client.Timeout <= 0 || !strings.HasPrefix(issuer, "https://") || !strings.HasPrefix(audience, "https://") {
		return nil, errors.New("trusted publishing configuration is invalid")
	}
	return &Service{db: db, driver: driver, repos: repos, issuer: issuer, audience: audience, client: client}, nil
}

func (s *Service) bind(position int) string {
	if s.driver == config.Postgres {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}

func (s *Service) tokenVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verifier != nil {
		return s.verifier, nil
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(oidc.ClientContext(discoveryCtx, s.client), s.issuer)
	if err != nil {
		return nil, ErrUnavailable
	}
	s.verifier = provider.VerifierContext(oidc.ClientContext(context.Background(), s.client), &oidc.Config{ClientID: s.audience, SupportedSigningAlgs: []string{oidc.RS256}})
	return s.verifier, nil
}

// CreatePublisher is for workspace managers. ref is exact, or a prefix ending
// in "*" such as refs/tags/v*.
func (s *Service) CreatePublisher(ctx context.Context, actor, workspace, repository, serviceAccount, githubRepo, ref, environment string) (Publisher, error) {
	if !githubRepository.MatchString(githubRepo) || !githubRefPattern.MatchString(ref) || (environment != "" && !environmentPattern.MatchString(environment)) {
		return Publisher{}, ErrInvalidPolicy
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Publisher{}, ErrUnavailable
	}
	publisher := Publisher{ID: id.String(), ServiceAccountID: serviceAccount, Repository: strings.ToLower(githubRepo), Ref: ref, Environment: environment, CreatedAt: time.Now().UTC().Truncate(time.Millisecond)}
	err = s.repos.WithRepositoryManagerTransaction(ctx, actor, workspace, repository, "", func(tx *sql.Tx, user string) error {
		if err := s.requireServiceAccount(ctx, tx, workspace, serviceAccount); err != nil {
			return err
		}
		var env any
		if environment != "" {
			env = environment
		}
		publisher.CreatedBy = user
		if _, err := tx.ExecContext(ctx, `INSERT INTO registry_trusted_publishers (publisher_id, workspace_id, repository_id, service_account_id, provider, subject_repository, subject_ref, subject_environment, created_by, created_at_ms) VALUES (`+s.bind(1)+`, `+s.bind(2)+`, `+s.bind(3)+`, `+s.bind(4)+`, 'github', `+s.bind(5)+`, `+s.bind(6)+`, `+s.bind(7)+`, `+s.bind(8)+`, `+s.bind(9)+`)`, publisher.ID, workspace, repository, serviceAccount, publisher.Repository, ref, env, user, publisher.CreatedAt.UnixMilli()); err != nil {
			return ErrUnavailable
		}
		return repositories.RecordAudit(ctx, tx, s.driver, user, "trusted_publisher.created", "trusted_publisher", publisher.ID)
	})
	if err != nil {
		return Publisher{}, err
	}
	return publisher, nil
}

func (s *Service) requireServiceAccount(ctx context.Context, tx *sql.Tx, workspace, serviceAccount string) error {
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM registry_service_accounts a JOIN registry_users u ON u.user_id = a.user_id WHERE a.user_id = `+s.bind(1)+` AND a.workspace_id = `+s.bind(2)+` AND u.status = 'active')`, serviceAccount, workspace).Scan(&ok); err != nil {
		return ErrUnavailable
	}
	if !ok {
		return ErrNotServiceAcct
	}
	return nil
}

func (s *Service) ListPublishers(ctx context.Context, actor, workspace, repository string) ([]Publisher, error) {
	var publishers []Publisher
	err := s.repos.WithRepositoryManagerTransaction(ctx, actor, workspace, repository, "", func(tx *sql.Tx, _ string) error {
		rows, err := tx.QueryContext(ctx, `SELECT publisher_id, service_account_id, subject_repository, COALESCE(subject_repository_id, ''), subject_ref, COALESCE(subject_environment, ''), created_by, created_at_ms FROM registry_trusted_publishers WHERE repository_id = `+s.bind(1)+` AND revoked_at_ms IS NULL ORDER BY publisher_id`, repository)
		if err != nil {
			return ErrUnavailable
		}
		defer rows.Close()
		for rows.Next() {
			var publisher Publisher
			var created int64
			if err := rows.Scan(&publisher.ID, &publisher.ServiceAccountID, &publisher.Repository, &publisher.RepositoryID, &publisher.Ref, &publisher.Environment, &publisher.CreatedBy, &created); err != nil {
				return ErrUnavailable
			}
			publisher.CreatedAt = time.UnixMilli(created).UTC()
			publishers = append(publishers, publisher)
		}
		return rows.Err()
	})
	return publishers, err
}

func (s *Service) RevokePublisher(ctx context.Context, actor, workspace, repository, publisherID string) error {
	return s.repos.WithRepositoryManagerTransaction(ctx, actor, workspace, repository, "", func(tx *sql.Tx, user string) error {
		result, err := tx.ExecContext(ctx, `UPDATE registry_trusted_publishers SET revoked_at_ms = `+s.bind(1)+` WHERE publisher_id = `+s.bind(2)+` AND repository_id = `+s.bind(3)+` AND revoked_at_ms IS NULL`, time.Now().UTC().UnixMilli(), publisherID, repository)
		if err != nil {
			return ErrUnavailable
		}
		if changed, _ := result.RowsAffected(); changed == 0 {
			return ErrUnknown
		}
		return repositories.RecordAudit(ctx, tx, s.driver, user, "trusted_publisher.revoked", "trusted_publisher", publisherID)
	})
}

type githubClaims struct {
	Repository   string `json:"repository"`
	RepositoryID string `json:"repository_id"`
	Ref          string `json:"ref"`
	Environment  string `json:"environment"`
	EventName    string `json:"event_name"`
	JTI          string `json:"jti"`
}

func refMatches(pattern, ref string) bool {
	if prefix, wildcard := strings.CutSuffix(pattern, "*"); wildcard {
		return strings.HasPrefix(ref, prefix) && len(ref) > len(prefix)
	}
	return pattern == ref
}

// Exchange verifies a GitHub Actions identity token for this registry's
// audience, matches it to a trusted publisher of the repository and issues
// tokens for that publisher's service account. Each identity token works once.
func (s *Service) Exchange(ctx context.Context, rawToken, workspace, repository string) (Exchanged, error) {
	if rawToken == "" || len(rawToken) > maxRawToken {
		return Exchanged{}, ErrRejected
	}
	verifier, err := s.tokenVerifier(ctx)
	if err != nil {
		return Exchanged{}, err
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	token, err := verifier.Verify(verifyCtx, rawToken)
	if err != nil || len(token.Audience) != 1 || token.Audience[0] != s.audience {
		return Exchanged{}, ErrRejected
	}
	var claims githubClaims
	if err := token.Claims(&claims); err != nil || claims.JTI == "" || len(claims.JTI) > 255 || claims.Repository == "" || claims.RepositoryID == "" || claims.Ref == "" {
		return Exchanged{}, ErrRejected
	}
	// pull_request_target runs with the base repository's context but may
	// execute code from a fork; it can never publish.
	if claims.EventName == "pull_request_target" {
		return Exchanged{}, ErrRejected
	}
	format, err := s.repos.RepositoryFormat(ctx, workspace, repository)
	if err != nil {
		return Exchanged{}, ErrNoPublisher
	}
	writeKind, ok := repositories.WriteTokenKindFor(format)
	if !ok {
		return Exchanged{}, ErrNoPublisher
	}

	var publisherID, serviceAccount string
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Exchanged{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT publisher_id, service_account_id, COALESCE(subject_repository_id, ''), subject_ref, COALESCE(subject_environment, '') FROM registry_trusted_publishers WHERE workspace_id = `+s.bind(1)+` AND repository_id = `+s.bind(2)+` AND revoked_at_ms IS NULL AND provider = 'github' AND subject_repository = `+s.bind(3)+` ORDER BY publisher_id`, workspace, repository, strings.ToLower(claims.Repository))
	if err != nil {
		return Exchanged{}, ErrUnavailable
	}
	pinned := ""
	for rows.Next() {
		var id, account, repositoryID, ref, environment string
		if err := rows.Scan(&id, &account, &repositoryID, &ref, &environment); err != nil {
			_ = rows.Close()
			return Exchanged{}, ErrUnavailable
		}
		if repositoryID != "" && repositoryID != claims.RepositoryID {
			continue
		}
		if !refMatches(ref, claims.Ref) || (environment != "" && environment != claims.Environment) {
			continue
		}
		publisherID, serviceAccount, pinned = id, account, repositoryID
		break
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return Exchanged{}, ErrUnavailable
	}
	if publisherID == "" {
		return Exchanged{}, ErrNoPublisher
	}
	// The GitHub repository ID is pinned on first use: a repository deleted
	// and recreated under the same name by someone else no longer matches.
	if pinned == "" {
		if _, err := tx.ExecContext(ctx, `UPDATE registry_trusted_publishers SET subject_repository_id = `+s.bind(1)+` WHERE publisher_id = `+s.bind(2)+` AND subject_repository_id IS NULL`, claims.RepositoryID, publisherID); err != nil {
			return Exchanged{}, ErrUnavailable
		}
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `DELETE FROM registry_trusted_publishing_tokens WHERE expires_at_ms < `+s.bind(1), now.UnixMilli()); err != nil {
		return Exchanged{}, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO registry_trusted_publishing_tokens (token_id, provider, expires_at_ms) VALUES (`+s.bind(1)+`, 'github', `+s.bind(2)+`)`, claims.JTI, token.Expiry.UTC().UnixMilli()); err != nil {
		return Exchanged{}, ErrReplay
	}
	if err := repositories.RecordAudit(ctx, tx, s.driver, serviceAccount, "trusted_publishing.exchanged", "trusted_publisher", publisherID); err != nil {
		return Exchanged{}, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return Exchanged{}, ErrUnavailable
	}

	result := Exchanged{Publisher: publisherID}
	write, err := s.repos.IssueToken(ctx, serviceAccount, workspace, repository, writeKind, TokenTTL)
	if err != nil {
		return Exchanged{}, fmt.Errorf("%w: the service account could not receive a write token: %v", ErrNoPublisher, err)
	}
	result.Write = write
	if read, err := s.repos.IssueToken(ctx, serviceAccount, workspace, repository, repositories.TokenRead, TokenTTL); err == nil {
		result.Read = read
	}
	return result, nil
}
