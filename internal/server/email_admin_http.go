package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/email"
)

// EmailOutbox is implemented by the email outbox.
type EmailOutbox interface {
	Status(ctx context.Context) (email.Status, error)
	Failures(ctx context.Context, limit int) ([]email.Failure, error)
	Resend(ctx context.Context, actorUserID, jobID string) (string, error)
}

type emailFailureResponse struct {
	JobID     string `json:"job_id"`
	Template  string `json:"template"`
	Provider  string `json:"provider,omitempty"`
	Error     string `json:"error"`
	Recipient string `json:"recipient"`
	Attempts  int    `json:"attempts"`
	FailedAt  string `json:"failed_at"`
}

type emailStatusResponse struct {
	Enabled         bool                   `json:"enabled"`
	Provider        string                 `json:"provider,omitempty"`
	Health          string                 `json:"health,omitempty"`
	Pending         int                    `json:"pending"`
	OldestPendingAt string                 `json:"oldest_pending_at,omitempty"`
	Failed          int                    `json:"failed"`
	Failures        []emailFailureResponse `json:"failures"`
}

// A message waiting longer than this means the provider is not taking mail.
const emailStalledAfter = 30 * time.Minute

func (h *authHTTP) registerEmailAdminRoutes(router chi.Router) {
	router.Get("/api/v1/admin/email", h.emailStatus)
	router.Post("/api/v1/admin/email/failures/{jobID}/resend", h.resendEmail)
}

// emailStatus is for installation administrators. health is "ok",
// "failing" (messages were given up on) or "stalled" (a message has been
// waiting for 30 minutes), so external monitoring can alert on it.
func (h *authHTTP) emailStatus(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	if err := h.repositories.RequireInstanceAdministrator(request.Context(), session.UserID); err != nil {
		writeRepositoryError(response, err)
		return
	}
	result := emailStatusResponse{Failures: []emailFailureResponse{}}
	if h.email == nil {
		writeJSON(response, http.StatusOK, result)
		return
	}
	status, err := h.email.Status(request.Context())
	if err != nil {
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	failures, err := h.email.Failures(request.Context(), 100)
	if err != nil {
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	result.Enabled, result.Provider, result.Pending, result.Failed = true, status.Provider, status.Pending, status.Failed
	result.Health = "ok"
	if status.Failed > 0 {
		result.Health = "failing"
	}
	if !status.OldestPending.IsZero() {
		result.OldestPendingAt = status.OldestPending.Format(time.RFC3339Nano)
		if time.Since(status.OldestPending) > emailStalledAfter {
			result.Health = "stalled"
		}
	}
	for _, item := range failures {
		result.Failures = append(result.Failures, emailFailureResponse{JobID: item.JobID, Template: string(item.Template), Provider: item.Provider, Error: item.Error, Recipient: item.Recipient, Attempts: item.Attempts, FailedAt: item.FailedAt.Format(time.RFC3339Nano)})
	}
	writeJSON(response, http.StatusOK, result)
}

// resendEmail needs recent MFA, like other administrative mutations.
func (h *authHTTP) resendEmail(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	if err := h.repositories.RequireInstanceAdministrator(request.Context(), actor); err != nil {
		writeRepositoryError(response, err)
		return
	}
	if h.email == nil {
		writeAPIError(response, http.StatusConflict, "email_unavailable")
		return
	}
	jobID, err := h.email.Resend(request.Context(), actor, chi.URLParam(request, "jobID"))
	if errors.Is(err, email.ErrFailureUnknown) {
		writeAPIError(response, http.StatusNotFound, "email_failure_unknown")
		return
	} else if err != nil {
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	writeJSON(response, http.StatusAccepted, struct {
		JobID string `json:"job_id"`
	}{jobID})
}
