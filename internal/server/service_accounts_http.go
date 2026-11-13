package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/repositories"
	"private-registry/internal/trustedpub"
	"private-registry/internal/workspaces"
)

type serviceAccountResponse struct {
	UserID      string `json:"user_id"`
	Description string `json:"description"`
	Status      string `json:"status"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
}

type serviceTokenResponse struct {
	TokenID      string `json:"token_id"`
	Kind         string `json:"kind"`
	WorkspaceID  string `json:"workspace_id,omitempty"`
	RepositoryID string `json:"repository_id,omitempty"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
	Revoked      bool   `json:"revoked,omitempty"`
	Bearer       string `json:"bearer,omitempty"`
}

type trustedPublisherResponse struct {
	PublisherID      string `json:"publisher_id"`
	ServiceAccountID string `json:"service_account_id"`
	Repository       string `json:"repository"`
	RepositoryID     string `json:"repository_id,omitempty"`
	Ref              string `json:"ref"`
	Environment      string `json:"environment,omitempty"`
	CreatedAt        string `json:"created_at"`
}

func (h *authHTTP) registerServiceAccountRoutes(router chi.Router) {
	base := "/api/v1/workspaces/{workspaceID}/service-accounts"
	router.Post(base, h.createServiceAccount)
	router.Get(base, h.listServiceAccounts)
	router.Delete(base+"/{userID}", h.disableServiceAccount)
	router.Post(base+"/{userID}/tokens", h.issueServiceAccountToken)
	router.Get(base+"/{userID}/tokens", h.listServiceAccountTokens)
	router.Delete(base+"/{userID}/tokens/{kind}/{tokenID}", h.revokeServiceAccountToken)
	if h.trustedPublishing != nil {
		publishers := "/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/trusted-publishers"
		router.Post(publishers, h.createTrustedPublisher)
		router.Get(publishers, h.listTrustedPublishers)
		router.Delete(publishers+"/{publisherID}", h.revokeTrustedPublisher)
		router.Post("/api/v1/trusted-publishing/github/exchange", h.exchangeTrustedPublishing)
	}
}

func writeServiceAccountError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, workspaces.ErrServiceAccountUnavailable), errors.Is(err, trustedpub.ErrUnknown):
		writeAPIError(response, http.StatusNotFound, "not_found")
	case errors.Is(err, workspaces.ErrServiceAccountRole):
		writeAPIError(response, http.StatusConflict, "service_account_role")
	case errors.Is(err, repositories.ErrInvalidTokenKind), errors.Is(err, trustedpub.ErrInvalidPolicy):
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, trustedpub.ErrNotServiceAcct):
		writeAPIError(response, http.StatusConflict, "not_a_service_account")
	case errors.Is(err, trustedpub.ErrUnavailable):
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
	case errors.Is(err, workspaces.ErrForbidden), errors.Is(err, workspaces.ErrUnauthenticated), errors.Is(err, workspaces.ErrInvalidWorkspaceID), errors.Is(err, workspaces.ErrInvalidName):
		writeWorkspaceError(response, err)
	default:
		writeRepositoryError(response, err)
	}
}

func (h *authHTTP) createServiceAccount(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	var payload struct {
		Description string `json:"description"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	account, err := h.workspaces.CreateServiceAccount(request.Context(), actor, chi.URLParam(request, "workspaceID"), payload.Description)
	if err != nil {
		writeServiceAccountError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, serviceAccountResponse{UserID: account.UserID, Description: account.Description, Status: account.Status, CreatedBy: account.CreatedBy, CreatedAt: account.CreatedAt.Format(time.RFC3339Nano)})
}

func (h *authHTTP) listServiceAccounts(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	accounts, err := h.workspaces.ListServiceAccounts(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"))
	if err != nil {
		writeServiceAccountError(response, err)
		return
	}
	items := make([]serviceAccountResponse, 0, len(accounts))
	for _, account := range accounts {
		items = append(items, serviceAccountResponse{UserID: account.UserID, Description: account.Description, Status: account.Status, CreatedBy: account.CreatedBy, CreatedAt: account.CreatedAt.Format(time.RFC3339Nano)})
	}
	writeJSON(response, http.StatusOK, struct {
		ServiceAccounts []serviceAccountResponse `json:"service_accounts"`
	}{items})
}

func (h *authHTTP) disableServiceAccount(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	if err := h.workspaces.DisableServiceAccount(request.Context(), actor, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "userID")); err != nil {
		writeServiceAccountError(response, err)
		return
	}
	writeNoContent(response)
}

// issueServiceAccountToken issues a token owned by the service account. The
// account's own grants decide what the token can do.
func (h *authHTTP) issueServiceAccountToken(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	var payload struct {
		RepositoryID string `json:"repository_id"`
		Kind         string `json:"kind"`
		TTLSeconds   int64  `json:"ttl_seconds"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	if payload.TTLSeconds < 0 || payload.TTLSeconds > int64((30*24*time.Hour)/time.Second) {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	workspace, account := chi.URLParam(request, "workspaceID"), chi.URLParam(request, "userID")
	if err := h.workspaces.RequireServiceAccountManager(request.Context(), actor, workspace, account); err != nil {
		writeServiceAccountError(response, err)
		return
	}
	token, err := h.repositories.IssueToken(request.Context(), account, workspace, payload.RepositoryID, repositories.TokenKind(payload.Kind), time.Duration(payload.TTLSeconds)*time.Second)
	if err != nil {
		writeServiceAccountError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, serviceTokenResponse{TokenID: token.ID, Kind: string(token.Kind), WorkspaceID: workspace, RepositoryID: payload.RepositoryID, CreatedAt: token.CreatedAt.Format(time.RFC3339Nano), ExpiresAt: token.ExpiresAt.Format(time.RFC3339Nano), Bearer: token.Bearer})
}

func (h *authHTTP) listServiceAccountTokens(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	workspace, account := chi.URLParam(request, "workspaceID"), chi.URLParam(request, "userID")
	if err := h.workspaces.RequireServiceAccountManager(request.Context(), session.UserID, workspace, account); err != nil {
		writeServiceAccountError(response, err)
		return
	}
	tokens, err := h.repositories.ListTokens(request.Context(), account)
	if err != nil {
		writeServiceAccountError(response, err)
		return
	}
	items := make([]serviceTokenResponse, 0, len(tokens))
	for _, token := range tokens {
		items = append(items, serviceTokenResponse{TokenID: token.ID, Kind: string(token.Kind), WorkspaceID: token.WorkspaceID, RepositoryID: token.RepositoryID, CreatedAt: token.CreatedAt.Format(time.RFC3339Nano), ExpiresAt: token.ExpiresAt.Format(time.RFC3339Nano), Revoked: token.Revoked})
	}
	writeJSON(response, http.StatusOK, struct {
		Tokens []serviceTokenResponse `json:"tokens"`
	}{items})
}

func (h *authHTTP) revokeServiceAccountToken(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	workspace, account := chi.URLParam(request, "workspaceID"), chi.URLParam(request, "userID")
	if err := h.workspaces.RequireServiceAccountManager(request.Context(), actor, workspace, account); err != nil {
		writeServiceAccountError(response, err)
		return
	}
	if err := h.repositories.RevokeToken(request.Context(), account, repositories.TokenKind(chi.URLParam(request, "kind")), chi.URLParam(request, "tokenID")); err != nil {
		writeServiceAccountError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) createTrustedPublisher(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	var payload struct {
		ServiceAccountID string `json:"service_account_id"`
		Repository       string `json:"repository"`
		Ref              string `json:"ref"`
		Environment      string `json:"environment"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	publisher, err := h.trustedPublishing.CreatePublisher(request.Context(), actor, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), payload.ServiceAccountID, payload.Repository, payload.Ref, payload.Environment)
	if err != nil {
		writeServiceAccountError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, trustedPublisherResponse{PublisherID: publisher.ID, ServiceAccountID: publisher.ServiceAccountID, Repository: publisher.Repository, Ref: publisher.Ref, Environment: publisher.Environment, CreatedAt: publisher.CreatedAt.Format(time.RFC3339Nano)})
}

func (h *authHTTP) listTrustedPublishers(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	publishers, err := h.trustedPublishing.ListPublishers(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"))
	if err != nil {
		writeServiceAccountError(response, err)
		return
	}
	items := make([]trustedPublisherResponse, 0, len(publishers))
	for _, publisher := range publishers {
		items = append(items, trustedPublisherResponse{PublisherID: publisher.ID, ServiceAccountID: publisher.ServiceAccountID, Repository: publisher.Repository, RepositoryID: publisher.RepositoryID, Ref: publisher.Ref, Environment: publisher.Environment, CreatedAt: publisher.CreatedAt.Format(time.RFC3339Nano)})
	}
	writeJSON(response, http.StatusOK, struct {
		TrustedPublishers []trustedPublisherResponse `json:"trusted_publishers"`
	}{items})
}

func (h *authHTTP) revokeTrustedPublisher(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	if err := h.trustedPublishing.RevokePublisher(request.Context(), actor, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), chi.URLParam(request, "publisherID")); err != nil {
		writeServiceAccountError(response, err)
		return
	}
	writeNoContent(response)
}

// exchangeTrustedPublishing has no session: the GitHub identity token is the
// credential. Failures share the per-source budget of personal tokens.
func (h *authHTTP) exchangeTrustedPublishing(response http.ResponseWriter, request *http.Request) {
	if !h.ociCanonical(request) {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return
	}
	var payload struct {
		Token        string `json:"token"`
		WorkspaceID  string `json:"workspace_id"`
		RepositoryID string `json:"repository_id"`
	}
	if status := decodeJSONBodyLimit(response, request, &payload, 32<<10); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	if !h.beginInvitationAttempt(response, request) {
		return
	}
	exchanged, err := h.trustedPublishing.Exchange(request.Context(), payload.Token, payload.WorkspaceID, payload.RepositoryID)
	switch {
	case errors.Is(err, trustedpub.ErrRejected), errors.Is(err, trustedpub.ErrNoPublisher):
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
		return
	case errors.Is(err, trustedpub.ErrReplay):
		writeAPIError(response, http.StatusUnauthorized, "token_already_used")
		return
	case err != nil:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	h.completeInvitationAttempt(request)
	result := struct {
		Write serviceTokenResponse  `json:"write"`
		Read  *serviceTokenResponse `json:"read,omitempty"`
	}{Write: serviceTokenResponse{TokenID: exchanged.Write.ID, Kind: string(exchanged.Write.Kind), CreatedAt: exchanged.Write.CreatedAt.Format(time.RFC3339Nano), ExpiresAt: exchanged.Write.ExpiresAt.Format(time.RFC3339Nano), Bearer: exchanged.Write.Bearer}}
	if exchanged.Read.Bearer != "" {
		result.Read = &serviceTokenResponse{TokenID: exchanged.Read.ID, Kind: string(exchanged.Read.Kind), CreatedAt: exchanged.Read.CreatedAt.Format(time.RFC3339Nano), ExpiresAt: exchanged.Read.ExpiresAt.Format(time.RFC3339Nano), Bearer: exchanged.Read.Bearer}
	}
	writeJSON(response, http.StatusOK, result)
}
