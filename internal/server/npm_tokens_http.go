package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/repositories"
)

func (h *authHTTP) issueNPMWriteToken(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload struct {
		TTLSeconds int64 `json:"ttl_seconds"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return
	}
	if payload.TTLSeconds < 0 || payload.TTLSeconds > int64((30*24*time.Hour)/time.Second) {
		writeRepositoryError(response, repositories.ErrInvalidPersonalTokenRequest)
		return
	}
	workspace, repository := chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID")
	token, err := h.repositories.IssueNPMWriteToken(request.Context(), session.UserID, workspace, repository, time.Duration(payload.TTLSeconds)*time.Second)
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	item := personalTokenItemResponse{TokenID: token.ID, WorkspaceID: workspace, RepositoryID: repository, CreatedAt: token.CreatedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: token.ExpiresAt.UTC().Format(time.RFC3339Nano)}
	writeJSON(response, http.StatusCreated, issuedPersonalTokenResponse{Token: item, Bearer: token.Bearer})
}

func (h *authHTTP) listNPMWriteTokens(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	query := request.URL.Query()
	for name, values := range query {
		if (name != "after_token_id" && name != "limit") || len(values) != 1 {
			writeRepositoryError(response, repositories.ErrInvalidPersonalTokenRequest)
			return
		}
	}
	after := ""
	if values, exists := query["after_token_id"]; exists {
		after = values[0]
		if strings.TrimSpace(after) == "" {
			writeRepositoryError(response, repositories.ErrInvalidPersonalTokenRequest)
			return
		}
	}
	limit := 50
	if values, exists := query["limit"]; exists {
		var err error
		limit, err = strconv.Atoi(values[0])
		if err != nil || limit < 1 || limit > 100 {
			writeRepositoryError(response, repositories.ErrInvalidPersonalTokenRequest)
			return
		}
	}
	tokens, more, err := h.repositories.ListNPMWriteTokens(request.Context(), session.UserID, after, limit)
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	result := personalTokenListResponse{Tokens: make([]personalTokenItemResponse, 0, len(tokens)), HasMore: more}
	for _, token := range tokens {
		result.Tokens = append(result.Tokens, personalTokenItemResponse{TokenID: token.ID, WorkspaceID: token.WorkspaceID, RepositoryID: token.RepositoryID, CreatedAt: token.CreatedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: token.ExpiresAt.UTC().Format(time.RFC3339Nano), Revoked: token.Revoked})
	}
	if more {
		result.NextCursor = tokens[len(tokens)-1].ID
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *authHTTP) revokeNPMWriteToken(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return
	}
	if err := h.repositories.RevokeNPMWriteToken(request.Context(), session.UserID, chi.URLParam(request, "tokenID")); err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeNoContent(response)
}
