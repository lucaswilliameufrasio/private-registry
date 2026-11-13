package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// muiraVerifier is only an identity-token verification primitive. Its caller
// owns authorization, state and PKCE validation, account linking and sessions.
// The caller must inject a restricted HTTP client; this package does not
// establish a process-wide network boundary.
type muiraVerifier struct {
	verifier *oidc.IDTokenVerifier
	clientID string
	endpoint oauth2.Endpoint
}

func newMuiraVerifier(ctx context.Context, issuer, clientID string, client *http.Client) (*muiraVerifier, error) {
	if ctx == nil || client == nil || client.Timeout <= 0 || clientID == "" || len(clientID) > 256 || strings.TrimSpace(clientID) != clientID {
		return nil, errors.New("Muira verifier configuration is invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("Muira discovery requires a deadline")
	}
	parsed, err := url.Parse(issuer)
	if err != nil || len(issuer) > 2048 || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.String() != issuer {
		return nil, errors.New("Muira issuer is invalid")
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), issuer)
	if err != nil {
		return nil, errors.New("Muira discovery failed")
	}
	endpoint := provider.Endpoint()
	// The restricted client only reaches the issuer origin; advertised
	// endpoints elsewhere would fail later, so refuse them at startup.
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL} {
		advertised, err := url.Parse(raw)
		if err != nil || advertised.Scheme != "https" || !strings.EqualFold(advertised.Host, parsed.Host) || advertised.User != nil || advertised.Fragment != "" {
			return nil, errors.New("Muira discovery advertised an endpoint outside the issuer origin")
		}
	}
	return &muiraVerifier{verifier: provider.VerifierContext(oidc.ClientContext(context.Background(), client), &oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{oidc.RS256}}), clientID: clientID, endpoint: endpoint}, nil
}

func (v *muiraVerifier) verify(ctx context.Context, rawToken, expectedNonce string) (string, error) {
	if v == nil || v.verifier == nil || ctx == nil || len(rawToken) == 0 || len(rawToken) > 16<<10 || len(expectedNonce) == 0 || len(expectedNonce) > 255 {
		return "", ErrRejected
	}
	if _, ok := ctx.Deadline(); !ok {
		return "", ErrRejected
	}
	token, err := v.verifier.Verify(ctx, rawToken)
	if err != nil || len(token.Audience) != 1 || token.Audience[0] != v.clientID || subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(expectedNonce)) != 1 {
		return "", ErrRejected
	}
	id, err := uuid.Parse(token.Subject)
	if err != nil || id == uuid.Nil || id.Version() != 7 || id.String() != token.Subject {
		return "", ErrRejected
	}
	return token.Subject, nil
}
