package server

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/authattempts"
	"private-registry/internal/repositories"
)

type personalTokenItemResponse struct {
	TokenID      string `json:"token_id"`
	WorkspaceID  string `json:"workspace_id"`
	RepositoryID string `json:"repository_id"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
	Revoked      bool   `json:"revoked"`
}

type issuedPersonalTokenResponse struct {
	Token  personalTokenItemResponse `json:"token"`
	Bearer string                    `json:"bearer"`
}

type personalTokenListResponse struct {
	Tokens     []personalTokenItemResponse `json:"tokens"`
	HasMore    bool                        `json:"has_more"`
	NextCursor string                      `json:"next_cursor,omitempty"`
}

func personalTokenResponse(token repositories.PersonalReadToken) personalTokenItemResponse {
	return personalTokenItemResponse{TokenID: token.ID, WorkspaceID: token.WorkspaceID, RepositoryID: token.RepositoryID,
		CreatedAt: token.CreatedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: token.ExpiresAt.UTC().Format(time.RFC3339Nano), Revoked: token.Revoked}
}

func (h *authHTTP) issuePersonalReadToken(response http.ResponseWriter, request *http.Request) {
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
	token, err := h.repositories.IssuePersonalReadToken(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), time.Duration(payload.TTLSeconds)*time.Second)
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, issuedPersonalTokenResponse{Token: personalTokenResponse(token.PersonalReadToken), Bearer: token.Bearer})
}

func (h *authHTTP) listPersonalReadTokens(response http.ResponseWriter, request *http.Request) {
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
	tokens, more, err := h.repositories.ListPersonalReadTokens(request.Context(), session.UserID, after, limit)
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	result := personalTokenListResponse{Tokens: make([]personalTokenItemResponse, 0, len(tokens)), HasMore: more}
	for _, token := range tokens {
		result.Tokens = append(result.Tokens, personalTokenResponse(token))
	}
	if more {
		result.NextCursor = tokens[len(tokens)-1].ID
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *authHTTP) revokePersonalReadToken(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return
	}
	if err := h.repositories.RevokePersonalReadToken(request.Context(), session.UserID, chi.URLParam(request, "tokenID")); err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) authenticatePersonalToken(response http.ResponseWriter, request *http.Request) (string, bool) {
	select {
	case h.personalTokenSlots <- struct{}{}:
		defer func() {
			<-h.personalTokenSlots
		}()
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return "", false
	}
	source, err := clientAddress(request, h.trustedProxies)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return "", false
	}
	retryAfter, err := h.service.BeginPersonalToken(request.Context(), source)
	if err != nil {
		if errors.Is(err, authattempts.ErrRateLimited) {
			seconds := int64((retryAfter + time.Second - 1) / time.Second)
			if seconds < 1 {
				seconds = 1
			}
			response.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
			writeAPIError(response, http.StatusTooManyRequests, "rate_limited")
		} else {
			writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		}
		return "", false
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 128 {
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
		return "", false
	}
	userID, err := h.repositories.VerifyPersonalReadToken(request.Context(), parts[1], chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"))
	if errors.Is(err, repositories.ErrPersonalTokenUnavailable) {
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
		return "", false
	}
	if err != nil || h.service.CompletePersonalToken(request.Context(), source) != nil {
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return "", false
	}
	return userID, true
}

func (h *authHTTP) personalTokenManifest(response http.ResponseWriter, request *http.Request) {
	requestOrigin, err := normalizeOrigin("https://" + request.Host)
	if err != nil || requestOrigin != h.canonicalOrigin || !requestUsesHTTPS(request, h.trustedProxies) {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return
	}
	userID, ok := h.authenticatePersonalToken(response, request)
	if !ok {
		return
	}
	artifact, err := h.artifacts.GetPublishedVersion(request.Context(), userID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), chi.URLParam(request, "artifactVersionID"))
	if err != nil {
		writeArtifactError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, toArtifactVersionResponse(artifact))
}

func (h *authHTTP) personalTokenFile(response http.ResponseWriter, request *http.Request) {
	if !h.requireAssetRequest(response, request) {
		return
	}
	userID, ok := h.authenticatePersonalToken(response, request)
	if !ok {
		return
	}
	workspaceID, repositoryID, fileID := chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), chi.URLParam(request, "fileID")
	file, err := h.artifacts.ResolvePrivateFile(request.Context(), userID, workspaceID, repositoryID, fileID)
	if err != nil {
		writeArtifactError(response, err)
		return
	}
	etag := `"` + file.SHA256 + `"`
	setArtifactDownloadHeaders(response, file, etag)
	if matchesETag(request.Header.Values("If-None-Match"), etag) {
		response.WriteHeader(http.StatusNotModified)
		return
	}
	rangeHeader := ""
	ifRange := request.Header.Values("If-Range")
	if len(ifRange) == 0 || (len(ifRange) == 1 && strings.TrimSpace(ifRange[0]) == etag) {
		ranges := request.Header.Values("Range")
		if len(ranges) > 1 {
			response.Header().Del("Content-Length")
			writeUnsatisfiedRange(response, file.Size)
			return
		}
		if len(ranges) == 1 {
			rangeHeader = ranges[0]
		}
	}
	offset, length, partial, err := parseArtifactRange(rangeHeader, file.Size)
	if err != nil {
		response.Header().Del("Content-Length")
		writeUnsatisfiedRange(response, file.Size)
		return
	}
	opened, err := h.artifacts.OpenFile(request.Context(), userID, workspaceID, repositoryID, fileID, offset, length)
	if err != nil {
		for _, name := range []string{"Content-Type", "Content-Disposition", "Content-Length", "ETag", "Accept-Ranges"} {
			response.Header().Del(name)
		}
		writeArtifactError(response, err)
		return
	}
	defer opened.Reader.Close()
	response.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	status := http.StatusOK
	if partial {
		status = http.StatusPartialContent
		response.Header().Set("Content-Range", "bytes "+strconv.FormatInt(offset, 10)+"-"+strconv.FormatInt(offset+length-1, 10)+"/"+strconv.FormatInt(file.Size, 10))
	}
	response.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = io.Copy(response, opened.Reader)
	}
}
