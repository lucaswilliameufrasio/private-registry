package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/npm"
)

func (h *authHTTP) registerNPMReviewRoutes(router chi.Router) {
	base := "/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/npm"
	router.Get(base+"/review-policy", h.getNPMReviewPolicy)
	router.Put(base+"/review-policy", h.setNPMReviewPolicy)
	router.Put(base+"/reviewers/{userID}", h.grantNPMReviewer)
	router.Delete(base+"/reviewers/{userID}", h.revokeNPMReviewer)
	router.Get(base+"/reviews", h.listNPMReviews)
	router.Get(base+"/reviews/{reservationID}/archive", h.getNPMReviewArchive)
	router.Post(base+"/reviews/{reservationID}/approve", h.approveNPMReceipt)
	router.Post(base+"/reviews/{reservationID}/reject", h.rejectNPMReceipt)
}

func npmReviewScope(request *http.Request) (string, string, string) {
	return chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), chi.URLParam(request, "reservationID")
}

func writeNPMReviewError(response http.ResponseWriter, err error) {
	if errors.Is(err, npm.ErrReviewUnavailable) {
		writeAPIError(response, http.StatusNotFound, "review_unavailable")
		return
	}
	writeGoManagementError(response, err)
}

func (h *authHTTP) getNPMReviewPolicy(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := npmReviewScope(request)
	policy, err := h.repositories.NPMReviewPolicy(request.Context(), session.UserID, workspace, repository)
	if err != nil {
		writeNPMReviewError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		Required bool  `json:"required"`
		Revision int64 `json:"revision"`
	}{policy.Required, policy.Revision})
}

func (h *authHTTP) setNPMReviewPolicy(response http.ResponseWriter, request *http.Request) {
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
	workspace, repository, _ := npmReviewScope(request)
	policy, err := h.repositories.SetNPMReviewPolicy(request.Context(), actor, workspace, repository, *payload.ExpectedRevision, *payload.Required)
	if err != nil {
		writeNPMReviewError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		Required bool  `json:"required"`
		Revision int64 `json:"revision"`
	}{policy.Required, policy.Revision})
}

func (h *authHTTP) grantNPMReviewer(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := npmReviewScope(request)
	id, err := h.repositories.GrantNPMReviewer(request.Context(), actor, workspace, repository, chi.URLParam(request, "userID"))
	if err != nil {
		writeNPMReviewError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		ID string `json:"grant_id"`
	}{id})
}

func (h *authHTTP) revokeNPMReviewer(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := npmReviewScope(request)
	if err := h.repositories.RevokeNPMReviewer(request.Context(), actor, workspace, repository, chi.URLParam(request, "userID")); err != nil {
		writeNPMReviewError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) listNPMReviews(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	query := request.URL.Query()
	for name, values := range query {
		if (name != "after_reservation_id" && name != "limit") || len(values) != 1 || strings.TrimSpace(values[0]) == "" {
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
	workspace, repository, _ := npmReviewScope(request)
	items, more, err := h.npmReservations.ListReviewCandidates(request.Context(), session.UserID, workspace, repository, query.Get("after_reservation_id"), limit)
	if err != nil {
		writeNPMReviewError(response, err)
		return
	}
	type review struct {
		ID          string `json:"reservation_id"`
		Name        string `json:"name"`
		Version     string `json:"version"`
		PublisherID string `json:"publisher_id"`
	}
	result := struct {
		Reviews    []review `json:"reviews"`
		HasMore    bool     `json:"has_more"`
		NextCursor string   `json:"next_cursor,omitempty"`
	}{Reviews: make([]review, 0, len(items)), HasMore: more}
	for _, item := range items {
		result.Reviews = append(result.Reviews, review{item.ID, item.Name, item.Version, item.PublisherID})
	}
	if more {
		result.NextCursor = items[len(items)-1].ID
	}
	response.Header().Set("Cache-Control", "private, no-store")
	writeJSON(response, http.StatusOK, result)
}

func (h *authHTTP) getNPMReviewArchive(response http.ResponseWriter, request *http.Request) {
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
	workspace, repository, id := npmReviewScope(request)
	reader, size, err := h.npmReceipts.OpenReviewArchive(ctx, session.UserID, workspace, repository, id)
	if err != nil {
		writeNPMReviewError(response, err)
		return
	}
	defer reader.Close()
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Content-Disposition", "attachment")
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	response.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(response, reader, size)
}

func (h *authHTTP) approveNPMReceipt(response http.ResponseWriter, request *http.Request) {
	h.decideNPMReceipt(response, request, "approved")
}

func (h *authHTTP) rejectNPMReceipt(response http.ResponseWriter, request *http.Request) {
	h.decideNPMReceipt(response, request, "rejected")
}

func (h *authHTTP) decideNPMReceipt(response http.ResponseWriter, request *http.Request, decision string) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	reason := ""
	if decision == "rejected" {
		var cancel context.CancelFunc
		request, cancel, ok = goRequestContext(response, request, true)
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
		reason = payload.Reason
	}
	workspace, repository, id := npmReviewScope(request)
	if _, err := h.npmReservations.DecideReview(request.Context(), actor, workspace, repository, id, decision, reason); err != nil {
		writeNPMReviewError(response, err)
		return
	}
	writeNoContent(response)
}
