package server

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/gomod"
	"private-registry/internal/repositories"
)

const (
	goMetadataBodyLimit = 24 << 20
	goRequestTimeout    = 5 * time.Minute
)

func (h *authHTTP) registerGoManagementRoutes(router chi.Router) {
	base := "/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/go"
	router.Post(base+"/uploads", h.reserveGoUpload)
	router.Get(base+"/uploads/{uploadSessionID}", h.getGoUpload)
	router.Put(base+"/uploads/{uploadSessionID}/content", h.receiveGoUpload)
	router.Post(base+"/uploads/{uploadSessionID}/publish", h.publishGoUpload)
	router.Post(base+"/uploads/{uploadSessionID}/cancel", h.cancelGoUpload)
	router.Get(base+"/review-policy", h.getGoReviewPolicy)
	router.Put(base+"/review-policy", h.setGoReviewPolicy)
	router.Get(base+"/namespace-policy", h.getGoNamespacePolicy)
	router.Put(base+"/namespace-policy", h.setGoNamespacePolicy)
	router.Put(base+"/reviewers/{userID}", h.grantGoReviewer)
	router.Delete(base+"/reviewers/{userID}", h.revokeGoReviewer)
	router.Get(base+"/reviews", h.listGoReviews)
	router.Get(base+"/reviews/{uploadSessionID}/mod", h.getGoReviewMod)
	router.Get(base+"/reviews/{uploadSessionID}/zip", h.getGoReviewZip)
	router.Post(base+"/reviews/{uploadSessionID}/approve", h.approveGoUpload)
	router.Post(base+"/reviews/{uploadSessionID}/reject", h.rejectGoUpload)
}

func (h *authHTTP) goMutation(response http.ResponseWriter, request *http.Request) (string, bool) {
	if !h.requireCanonicalRequest(response, request) {
		return "", false
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return "", false
	}
	return session.UserID, true
}

func goRequestContext(response http.ResponseWriter, request *http.Request, body bool) (*http.Request, context.CancelFunc, bool) {
	deadline := time.Now().Add(goRequestTimeout)
	if body {
		if err := http.NewResponseController(response).SetReadDeadline(deadline); err != nil {
			writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
			return request, func() {}, false
		}
	}
	ctx, cancel := context.WithDeadline(request.Context(), deadline)
	return request.WithContext(ctx), func() {
		cancel()
		if body {
			_ = http.NewResponseController(response).SetReadDeadline(time.Time{})
		}
	}, true
}

func goScope(request *http.Request) (string, string, string) {
	return chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), chi.URLParam(request, "uploadSessionID")
}

func (h *authHTTP) reserveGoUpload(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := goScope(request)
	allowed, err := h.repositories.HasRepositoryGrant(request.Context(), actor, workspace, repository, repositories.GrantPublisher)
	if err != nil || !allowed {
		if err == nil {
			err = repositories.ErrForbidden
		}
		writeGoManagementError(response, err)
		return
	}
	select {
	case h.goMetadataSlots <- struct{}{}:
		defer func() { <-h.goMetadataSlots }()
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	request, cancel, ok := goRequestContext(response, request, true)
	if !ok {
		return
	}
	defer cancel()
	var payload struct {
		ModulePath string `json:"module_path"`
		Version    string `json:"version"`
		SourceTime string `json:"source_time"`
		GoMod      string `json:"go_mod"`
		ZipSize    *int64 `json:"zip_size"`
		ZipSHA256  string `json:"zip_sha256"`
	}
	if status := decodeJSONBodyLimit(response, request, &payload, goMetadataBodyLimit); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	sourceTime, err := time.Parse(time.RFC3339Nano, payload.SourceTime)
	if err != nil || payload.ZipSize == nil {
		writeGoManagementError(response, gomod.ErrInvalidPublication)
		return
	}
	reservation, err := h.goModules.ReservePublication(request.Context(), actor, workspace, repository, gomod.ReservationRequest{ModulePath: payload.ModulePath, Version: payload.Version, SourceTime: sourceTime, ModBytes: []byte(payload.GoMod), ZipSize: *payload.ZipSize, ZipSHA256: payload.ZipSHA256})
	if err != nil {
		writeGoManagementError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		ID        string `json:"upload_session_id"`
		ExpiresAt string `json:"expires_at"`
	}{reservation.ID, reservation.ExpiresAt.Format(time.RFC3339Nano)})
}

func (h *authHTTP) getGoUpload(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	workspace, repository, id := goScope(request)
	item, err := h.goModules.GetReservation(request.Context(), session.UserID, workspace, repository, id)
	if err != nil {
		writeGoManagementError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "private, no-store")
	writeJSON(response, http.StatusOK, struct {
		ID          string `json:"upload_session_id"`
		ModulePath  string `json:"module_path"`
		Version     string `json:"version"`
		Status      string `json:"status"`
		ExpiresAt   string `json:"expires_at"`
		ReviewHeld  bool   `json:"review_held"`
		ReviewState string `json:"review_state"`
		Invalidated bool   `json:"recovery_invalidated"`
	}{item.ID, item.ModulePath, item.Version, item.Status, item.ExpiresAt.Format(time.RFC3339Nano), item.ReviewHeld, item.ReviewState, item.Invalidated})
}

func (h *authHTTP) receiveGoUpload(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		writeAPIError(response, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	if request.ContentLength > h.goModules.MaxZipBytes() {
		writeAPIError(response, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	request, cancel, ok := goRequestContext(response, request, true)
	if !ok {
		return
	}
	defer cancel()
	workspace, repository, id := goScope(request)
	body := http.MaxBytesReader(response, request.Body, h.goModules.MaxZipBytes())
	if err := h.goModules.ReceiveReservation(request.Context(), actor, workspace, repository, id, body); err != nil {
		writeGoManagementError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) publishGoUpload(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	request, cancel, ok := goRequestContext(response, request, false)
	if !ok {
		return
	}
	defer cancel()
	workspace, repository, id := goScope(request)
	if err := h.goModules.PublishReservation(request.Context(), actor, workspace, repository, id); err != nil {
		writeGoManagementError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) cancelGoUpload(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	workspace, repository, id := goScope(request)
	if err := h.goModules.CancelReservation(request.Context(), actor, workspace, repository, id); err != nil {
		writeGoManagementError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) getGoReviewPolicy(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := goScope(request)
	policy, err := h.repositories.GoReviewPolicy(request.Context(), session.UserID, workspace, repository)
	if err != nil {
		writeGoManagementError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		Required bool  `json:"required"`
		Revision int64 `json:"revision"`
	}{policy.Required, policy.Revision})
}

func (h *authHTTP) setGoReviewPolicy(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	request, cancel, ok := goRequestContext(response, request, true)
	if !ok {
		return
	}
	defer cancel()
	var payload struct {
		Required         *bool  `json:"required"`
		ExpectedRevision *int64 `json:"expected_revision"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	if payload.Required == nil || payload.ExpectedRevision == nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	workspace, repository, _ := goScope(request)
	policy, err := h.repositories.SetGoReviewPolicy(request.Context(), actor, workspace, repository, *payload.ExpectedRevision, *payload.Required)
	if err != nil {
		writeGoManagementError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		Required bool  `json:"required"`
		Revision int64 `json:"revision"`
	}{policy.Required, policy.Revision})
}

type goNamespacePolicyResponse struct {
	Mode     string   `json:"mode"`
	Prefixes []string `json:"private_prefixes"`
	Revision int64    `json:"revision"`
}

func (h *authHTTP) getGoNamespacePolicy(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := goScope(request)
	policy, err := h.repositories.GoNamespacePolicy(request.Context(), session.UserID, workspace, repository)
	if err != nil {
		writeGoManagementError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, goNamespacePolicyResponse{Mode: policy.Mode, Prefixes: policy.Prefixes, Revision: policy.Revision})
}

func (h *authHTTP) setGoNamespacePolicy(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	request, cancel, ok := goRequestContext(response, request, true)
	if !ok {
		return
	}
	defer cancel()
	var payload struct {
		Mode             string   `json:"mode"`
		Prefixes         []string `json:"private_prefixes"`
		ExpectedRevision *int64   `json:"expected_revision"`
		ConfirmFallback  *bool    `json:"confirm_public_fallback"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	if payload.ExpectedRevision == nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	confirmed := payload.ConfirmFallback != nil && *payload.ConfirmFallback
	workspace, repository, _ := goScope(request)
	policy, err := h.repositories.SetGoNamespacePolicy(request.Context(), actor, workspace, repository, *payload.ExpectedRevision, payload.Mode, payload.Prefixes, confirmed)
	if err != nil {
		writeGoManagementError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, goNamespacePolicyResponse{Mode: policy.Mode, Prefixes: policy.Prefixes, Revision: policy.Revision})
}

func (h *authHTTP) grantGoReviewer(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := goScope(request)
	id, err := h.repositories.GrantGoReviewer(request.Context(), actor, workspace, repository, chi.URLParam(request, "userID"))
	if err != nil {
		writeGoManagementError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		ID string `json:"grant_id"`
	}{id})
}

func (h *authHTTP) revokeGoReviewer(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := goScope(request)
	if err := h.repositories.RevokeGoReviewer(request.Context(), actor, workspace, repository, chi.URLParam(request, "userID")); err != nil {
		writeGoManagementError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) listGoReviews(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	query := request.URL.Query()
	for name, values := range query {
		if (name != "after_upload_session_id" && name != "limit") || len(values) != 1 || strings.TrimSpace(values[0]) == "" {
			writeAPIError(response, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	limit := 50
	if raw := query.Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			writeAPIError(response, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	workspace, repository, _ := goScope(request)
	items, more, err := h.goModules.ListReviewCandidates(request.Context(), session.UserID, workspace, repository, query.Get("after_upload_session_id"), limit)
	if err != nil {
		writeGoManagementError(response, err)
		return
	}
	type review struct {
		ID          string `json:"upload_session_id"`
		ModulePath  string `json:"module_path"`
		Version     string `json:"version"`
		PublisherID string `json:"publisher_id"`
	}
	result := struct {
		Reviews    []review `json:"reviews"`
		HasMore    bool     `json:"has_more"`
		NextCursor string   `json:"next_cursor,omitempty"`
	}{Reviews: make([]review, 0, len(items)), HasMore: more}
	for _, item := range items {
		result.Reviews = append(result.Reviews, review{item.ID, item.ModulePath, item.Version, item.PublisherID})
	}
	if more {
		result.NextCursor = items[len(items)-1].ID
	}
	response.Header().Set("Cache-Control", "private, no-store")
	writeJSON(response, http.StatusOK, result)
}

func (h *authHTTP) getGoReviewMod(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	workspace, repository, id := goScope(request)
	item, err := h.goModules.GetReviewCandidate(request.Context(), session.UserID, workspace, repository, id)
	if err != nil {
		writeGoManagementError(response, err)
		return
	}
	if err := http.NewResponseController(response).SetWriteDeadline(time.Now().Add(goRequestTimeout)); err != nil {
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	defer func() { _ = http.NewResponseController(response).SetWriteDeadline(time.Time{}) }()
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = response.Write(item.Mod)
}

func (h *authHTTP) getGoReviewZip(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	deadline := time.Now().Add(goRequestTimeout)
	if err := http.NewResponseController(response).SetWriteDeadline(deadline); err != nil {
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	defer func() { _ = http.NewResponseController(response).SetWriteDeadline(time.Time{}) }()
	ctx, cancel := context.WithDeadline(request.Context(), deadline)
	defer cancel()
	workspace, repository, id := goScope(request)
	reader, size, err := h.goModules.OpenReviewZip(ctx, session.UserID, workspace, repository, id)
	if err != nil {
		writeGoManagementError(response, err)
		return
	}
	defer reader.Close()
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Content-Disposition", "attachment")
	response.Header().Set("Content-Type", "application/zip")
	response.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	response.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(response, reader, size)
}

func (h *authHTTP) approveGoUpload(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	workspace, repository, id := goScope(request)
	if err := h.goModules.ApproveReservation(request.Context(), actor, workspace, repository, id); err != nil {
		writeGoManagementError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) rejectGoUpload(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	request, cancel, ok := goRequestContext(response, request, true)
	if !ok {
		return
	}
	defer cancel()
	var payload struct {
		Reason string `json:"reason"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	workspace, repository, id := goScope(request)
	if err := h.goModules.RejectReservation(request.Context(), actor, workspace, repository, id, payload.Reason); err != nil {
		writeGoManagementError(response, err)
		return
	}
	writeNoContent(response)
}

func writeGoManagementError(response http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	switch {
	case errors.As(err, &maxBytesError):
		writeAPIError(response, http.StatusRequestEntityTooLarge, "request_too_large")
	case errors.Is(err, repositories.ErrUnauthenticated), errors.Is(err, repositories.ErrUserUnavailable):
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
	case errors.Is(err, repositories.ErrForbidden), errors.Is(err, repositories.ErrMembershipUnavailable):
		writeAPIError(response, http.StatusForbidden, "forbidden")
	case errors.Is(err, repositories.ErrInvalidWorkspaceID), errors.Is(err, repositories.ErrInvalidRepositoryID), errors.Is(err, gomod.ErrInvalidPublication), errors.Is(err, repositories.ErrGoNamespacePolicy):
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, gomod.ErrReservationUnavailable), errors.Is(err, repositories.ErrRepositoryUnavailable):
		writeAPIError(response, http.StatusNotFound, "upload_unavailable")
	case errors.Is(err, gomod.ErrReservationConflict), errors.Is(err, gomod.ErrVersionExists):
		writeAPIError(response, http.StatusConflict, "go_version_conflict")
	case errors.Is(err, gomod.ErrQuotaExceeded):
		writeAPIError(response, http.StatusConflict, "logical_quota_exceeded")
	case errors.Is(err, repositories.ErrReviewRequired):
		writeAPIError(response, http.StatusConflict, "human_review_required")
	case errors.Is(err, repositories.ErrReviewPolicyRevision):
		writeAPIError(response, http.StatusConflict, "review_policy_revision_conflict")
	case errors.Is(err, repositories.ErrGoNamespaceRevision):
		writeAPIError(response, http.StatusConflict, "namespace_policy_revision_conflict")
	case errors.Is(err, repositories.ErrGoNamespaceInUse):
		writeAPIError(response, http.StatusConflict, "private_namespace_in_use")
	case errors.Is(err, repositories.ErrGoNamespaceOutside):
		writeAPIError(response, http.StatusConflict, "private_namespace_required")
	case errors.Is(err, repositories.ErrGoNamespaceConfirm):
		writeAPIError(response, http.StatusPreconditionFailed, "public_fallback_confirmation_required")
	case errors.Is(err, repositories.ErrFormatMismatch):
		writeAPIError(response, http.StatusConflict, "repository_format_mismatch")
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
	}
}
