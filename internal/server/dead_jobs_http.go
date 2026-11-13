package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/repositories"
)

type deadJobResponse struct {
	ID          string `json:"job_id"`
	Kind        string `json:"kind"`
	Attempts    int    `json:"attempts"`
	MaxAttempts int    `json:"max_attempts"`
	FailureCode string `json:"failure_code"`
	Revision    int64  `json:"revision"`
	UpdatedAt   string `json:"updated_at"`
}

type deadJobListResponse struct {
	Jobs       []deadJobResponse `json:"jobs"`
	HasMore    bool              `json:"has_more"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

func (h *authHTTP) listDeadJobs(response http.ResponseWriter, request *http.Request) {
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
	jobs, hasMore, err := h.repositories.ListDeadJobs(request.Context(), session.UserID, after, limit)
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	result := deadJobListResponse{Jobs: make([]deadJobResponse, 0, len(jobs)), HasMore: hasMore}
	for _, job := range jobs {
		result.Jobs = append(result.Jobs, deadJobResponse{ID: job.ID, Kind: job.Kind, Attempts: job.Attempts, MaxAttempts: job.MaxAttempts, FailureCode: job.FailureCode, Revision: job.Revision, UpdatedAt: job.UpdatedAt.Format(time.RFC3339Nano)})
	}
	if hasMore {
		result.NextCursor = jobs[len(jobs)-1].ID
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *authHTTP) retryDeadJob(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload struct {
		ExpectedRevision *int64 `json:"expected_revision"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return
	}
	if payload.ExpectedRevision == nil {
		writeRepositoryError(response, repositories.ErrInvalidJobRequest)
		return
	}
	if err := h.repositories.RetryDeadJob(request.Context(), session.UserID, chi.URLParam(request, "jobID"), *payload.ExpectedRevision); err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeNoContent(response)
}
