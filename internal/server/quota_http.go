package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/repositories"
)

type logicalQuotaRequest struct {
	Mode             string          `json:"mode"`
	LimitBytes       json.RawMessage `json:"limit_bytes"`
	ExpectedRevision *int64          `json:"expected_revision"`
}

type logicalQuotaResponse struct {
	Mode       string `json:"mode"`
	LimitBytes *int64 `json:"limit_bytes,omitempty"`
	Revision   int64  `json:"revision"`
}

type genericLogicalUsageResponse struct {
	ReservedBytes  int64 `json:"reserved_bytes"`
	PublishedBytes int64 `json:"published_bytes"`
}

func (h *authHTTP) getGenericLogicalUsage(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	usage, err := h.repositories.WorkspaceGenericLogicalUsage(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"))
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, genericLogicalUsageResponse{ReservedBytes: usage.ReservedBytes, PublishedBytes: usage.PublishedBytes})
}

func quotaResponse(policy repositories.LogicalQuota) logicalQuotaResponse {
	result := logicalQuotaResponse{Mode: "unlimited", Revision: policy.Revision}
	if policy.LimitBytes != nil {
		result.Mode = "limited"
		result.LimitBytes = policy.LimitBytes
	}
	return result
}

func (h *authHTTP) getLogicalQuota(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	policy, err := h.repositories.LogicalQuotaPolicy(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"))
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, quotaResponse(policy))
}

func (h *authHTTP) setLogicalQuota(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload logicalQuotaRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return
	}
	var limit *int64
	if payload.ExpectedRevision == nil {
		writeRepositoryError(response, repositories.ErrInvalidQuota)
		return
	}
	switch payload.Mode {
	case "limited":
		var value int64
		if len(payload.LimitBytes) == 0 || string(payload.LimitBytes) == "null" || json.Unmarshal(payload.LimitBytes, &value) != nil || value < 0 {
			writeRepositoryError(response, repositories.ErrInvalidQuota)
			return
		}
		limit = &value
	case "unlimited":
		if len(payload.LimitBytes) != 0 {
			writeRepositoryError(response, repositories.ErrInvalidQuota)
			return
		}
	default:
		writeRepositoryError(response, repositories.ErrInvalidQuota)
		return
	}
	policy, err := h.repositories.SetLogicalQuotaPolicy(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), *payload.ExpectedRevision, limit)
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, quotaResponse(policy))
}
