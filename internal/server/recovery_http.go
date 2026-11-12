package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/auth"
)

func (h *authHTTP) registerRecoveryRoutes(router chi.Router) {
	router.Post("/api/v1/admin/users/{userID}/recovery", h.issueRecovery)
	router.Post("/api/v1/auth/recovery", h.completeRecovery)
}

func writeRecoveryError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrRecoveryUnavailable):
		writeAPIError(response, http.StatusNotFound, "recovery_unavailable")
	case errors.Is(err, auth.ErrRecoveryTarget):
		writeAPIError(response, http.StatusConflict, "recovery_target_invalid")
	case errors.Is(err, auth.ErrRecoveryForbidden):
		writeAPIError(response, http.StatusForbidden, "forbidden")
	case errors.Is(err, auth.ErrRecoveryPassword):
		writeAPIError(response, http.StatusBadRequest, "invalid_password")
	case errors.Is(err, auth.ErrBusy):
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
	default:
		writeServiceError(response, err)
	}
}

// issueRecovery is for installation administrators, with recent MFA. The
// link is handed to the person through a channel of the administrator's
// choice; the registry sends nothing.
func (h *authHTTP) issueRecovery(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	var payload struct {
		ResetMFA bool `json:"reset_mfa"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	issued, err := h.service.IssueRecovery(request.Context(), actor, chi.URLParam(request, "userID"), payload.ResetMFA)
	if err != nil {
		writeRecoveryError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, struct {
		RecoveryID string `json:"recovery_id"`
		ResetMFA   bool   `json:"reset_mfa"`
		ExpiresAt  string `json:"expires_at"`
		Token      string `json:"token"`
	}{issued.ID, issued.ResetMFA, issued.ExpiresAt.Format(time.RFC3339Nano), issued.Token})
}

// completeRecovery does not sign the person in: they sign in normally
// afterwards, enrolling new factors if those were reset.
func (h *authHTTP) completeRecovery(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	passwordValue := []byte(payload.Password)
	defer clear(passwordValue)
	if !h.beginInvitationAttempt(response, request) {
		return
	}
	if err := h.service.CompleteRecovery(request.Context(), payload.Token, passwordValue); err != nil {
		writeRecoveryError(response, err)
		return
	}
	h.completeInvitationAttempt(request)
	clearSessionCookies(response)
	writeNoContent(response)
}
