package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/repositories"
)

type recoveryJobResponse struct {
	ID             string `json:"job_id"`
	Kind           string `json:"kind"`
	PreviousStatus string `json:"previous_status"`
	Attempts       int    `json:"attempts"`
	MaxAttempts    int    `json:"max_attempts"`
	Revision       int64  `json:"revision"`
	UpdatedAt      string `json:"updated_at"`
}

func (h *authHTTP) listRecoveryJobs(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	query := request.URL.Query()
	for name, values := range query {
		if (name != "after_job_id" && name != "limit") || len(values) != 1 {
			writeRepositoryError(response, repositories.ErrInvalidJobRequest)
			return
		}
	}
	after := ""
	if values, exists := query["after_job_id"]; exists {
		after = values[0]
		if strings.TrimSpace(after) == "" {
			writeRepositoryError(response, repositories.ErrInvalidJobCursor)
			return
		}
	}
	limit := 50
	if values, exists := query["limit"]; exists {
		var err error
		limit, err = strconv.Atoi(values[0])
		if err != nil || limit < 1 || limit > 100 {
			writeRepositoryError(response, repositories.ErrInvalidJobRequest)
			return
		}
	}
	jobs, hasMore, err := h.repositories.ListRecoveryJobs(request.Context(), session.UserID, after, limit)
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	result := struct {
		Jobs       []recoveryJobResponse `json:"jobs"`
		HasMore    bool                  `json:"has_more"`
		NextCursor string                `json:"next_cursor,omitempty"`
	}{Jobs: make([]recoveryJobResponse, 0, len(jobs)), HasMore: hasMore}
	for _, job := range jobs {
		result.Jobs = append(result.Jobs, recoveryJobResponse{ID: job.ID, Kind: job.Kind, PreviousStatus: job.PreviousStatus, Attempts: job.Attempts, MaxAttempts: job.MaxAttempts, Revision: job.Revision, UpdatedAt: job.UpdatedAt.Format(time.RFC3339Nano)})
	}
	if hasMore {
		result.NextCursor = jobs[len(jobs)-1].ID
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *authHTTP) releaseRecoveryJob(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload struct {
		ExpectedRevision *int64 `json:"expected_revision"`
		ConfirmPolicies  *bool  `json:"confirm_destinations_and_policies"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return
	}
	if payload.ExpectedRevision == nil || payload.ConfirmPolicies == nil {
		writeRepositoryError(response, repositories.ErrInvalidJobRequest)
		return
	}
	if !*payload.ConfirmPolicies {
		writeAPIError(response, http.StatusPreconditionFailed, "recovery_policy_confirmation_required")
		return
	}
	if err := h.repositories.ReleaseRecoveryJob(request.Context(), session.UserID, chi.URLParam(request, "jobID"), *payload.ExpectedRevision); err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeNoContent(response)
}
