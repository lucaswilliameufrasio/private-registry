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
	"private-registry/internal/pub"
)

func (h *authHTTP) registerPubReviewRoutes(router chi.Router) {
	base := "/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/pub"
	router.Get(base+"/review-policy", h.getPubReviewPolicy)
	router.Put(base+"/review-policy", h.setPubReviewPolicy)
	router.Put(base+"/reviewers/{userID}", h.grantPubReviewer)
	router.Delete(base+"/reviewers/{userID}", h.revokePubReviewer)
	router.Get(base+"/reviews", h.listPubReviews)
	router.Get(base+"/reviews/{reservationID}/archive", h.getPubReviewArchive)
	router.Post(base+"/reviews/{reservationID}/approve", h.approvePubReceipt)
	router.Post(base+"/reviews/{reservationID}/reject", h.rejectPubReceipt)
}

func pubReviewScope(request *http.Request) (string, string, string) {
	return chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), chi.URLParam(request, "reservationID")
}

func writePubReviewError(response http.ResponseWriter, err error) {
	if errors.Is(err, pub.ErrReviewUnavailable) {
		writeAPIError(response, http.StatusNotFound, "review_unavailable")
		return
	}
	writeGoManagementError(response, err)
}

func (h *authHTTP) getPubReviewPolicy(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := pubReviewScope(request)
	policy, err := h.repositories.PubReviewPolicy(request.Context(), session.UserID, workspace, repository)
	if err != nil {
		writePubReviewError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		Required bool  `json:"required"`
		Revision int64 `json:"revision"`
	}{policy.Required, policy.Revision})
}

func (h *authHTTP) setPubReviewPolicy(response http.ResponseWriter, request *http.Request) {
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
	workspace, repository, _ := pubReviewScope(request)
	policy, err := h.repositories.SetPubReviewPolicy(request.Context(), actor, workspace, repository, *payload.ExpectedRevision, *payload.Required)
	if err != nil {
		writePubReviewError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		Required bool  `json:"required"`
		Revision int64 `json:"revision"`
	}{policy.Required, policy.Revision})
}

func (h *authHTTP) grantPubReviewer(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := pubReviewScope(request)
	id, err := h.repositories.GrantPubReviewer(request.Context(), actor, workspace, repository, chi.URLParam(request, "userID"))
	if err != nil {
		writePubReviewError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		ID string `json:"grant_id"`
	}{id})
}

func (h *authHTTP) revokePubReviewer(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := pubReviewScope(request)
	if err := h.repositories.RevokePubReviewer(request.Context(), actor, workspace, repository, chi.URLParam(request, "userID")); err != nil {
		writePubReviewError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) listPubReviews(response http.ResponseWriter, request *http.Request) {
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
	workspace, repository, _ := pubReviewScope(request)
	items, more, err := h.pubReservations.ListReviewCandidates(request.Context(), session.UserID, workspace, repository, query.Get("after_reservation_id"), limit)
	if err != nil {
		writePubReviewError(response, err)
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

func (h *authHTTP) getPubReviewArchive(response http.ResponseWriter, request *http.Request) {
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
	workspace, repository, id := pubReviewScope(request)
	reader, size, err := h.pubReceipts.OpenReviewArchive(ctx, session.UserID, workspace, repository, id)
	if err != nil {
		writePubReviewError(response, err)
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

func (h *authHTTP) approvePubReceipt(response http.ResponseWriter, request *http.Request) {
	h.decidePubReceipt(response, request, "approved")
}

func (h *authHTTP) rejectPubReceipt(response http.ResponseWriter, request *http.Request) {
	h.decidePubReceipt(response, request, "rejected")
}

func (h *authHTTP) decidePubReceipt(response http.ResponseWriter, request *http.Request, decision string) {
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
	workspace, repository, id := pubReviewScope(request)
	if _, err := h.pubReservations.DecideReview(request.Context(), actor, workspace, repository, id, decision, reason); err != nil {
		writePubReviewError(response, err)
		return
	}
	writeNoContent(response)
}
