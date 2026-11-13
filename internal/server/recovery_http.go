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
	router.Post("/api/v1/auth/recovery/request", h.requestRecovery)
	router.Get("/api/v1/account/email", h.getAccountEmail)
	router.Put("/api/v1/account/email", h.setAccountEmail)
	router.Post("/api/v1/auth/email/confirm", h.confirmEmail)
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
	case errors.Is(err, auth.ErrEmailUnavailable):
		writeAPIError(response, http.StatusConflict, "email_unavailable")
	case errors.Is(err, auth.ErrNoVerifiedEmail):
		writeAPIError(response, http.StatusConflict, "no_verified_email")
	case errors.Is(err, auth.ErrInvalidEmail):
		writeAPIError(response, http.StatusBadRequest, "invalid_email")
	case errors.Is(err, auth.ErrVerificationLimit):
		writeAPIError(response, http.StatusTooManyRequests, "too_many_requests")
	case errors.Is(err, auth.ErrVerificationGone):
		writeAPIError(response, http.StatusNotFound, "verification_unavailable")
	default:
		writeServiceError(response, err)
	}
}

// issueRecovery is for installation administrators, with recent MFA. With
// send_email the link goes to the account's confirmed address and is not
// returned; otherwise the administrator hands it over through a channel of
// their choice.
func (h *authHTTP) issueRecovery(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	var payload struct {
		ResetMFA  bool `json:"reset_mfa"`
		SendEmail bool `json:"send_email"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	issue := h.service.IssueRecovery
	if payload.SendEmail {
		issue = h.service.IssueRecoveryByEmail
	}
	issued, err := issue(request.Context(), actor, chi.URLParam(request, "userID"), payload.ResetMFA)
	if err != nil {
		writeRecoveryError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, struct {
		RecoveryID string `json:"recovery_id"`
		ResetMFA   bool   `json:"reset_mfa"`
		ExpiresAt  string `json:"expires_at"`
		Emailed    bool   `json:"emailed"`
		Token      string `json:"token,omitempty"`
	}{issued.ID, issued.ResetMFA, issued.ExpiresAt.Format(time.RFC3339Nano), payload.SendEmail, issued.Token})
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

// requestRecovery answers 202 whether or not the login name exists, has a
// confirmed address or was asked for recently. Every request counts against
// the source address's attempt budget.
func (h *authHTTP) requestRecovery(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	if !h.service.EmailEnabled() {
		writeAPIError(response, http.StatusConflict, "email_unavailable")
		return
	}
	var payload struct {
		LoginName string `json:"login_name"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	if !h.beginInvitationAttempt(response, request) {
		return
	}
	if err := h.service.RequestRecovery(request.Context(), payload.LoginName); err != nil {
		writeRecoveryError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, struct {
		Status string `json:"status"`
	}{"accepted"})
}

type accountEmailResponse struct {
	Email        string `json:"email,omitempty"`
	Verified     bool   `json:"verified"`
	PendingEmail string `json:"pending_email,omitempty"`
	Delivery     bool   `json:"delivery_enabled"`
}

func (h *authHTTP) getAccountEmail(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	current, err := h.service.AccountEmailOf(request.Context(), session.UserID)
	if err != nil {
		writeRecoveryError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, accountEmailResponse{Email: current.Address, Verified: current.Verified, PendingEmail: current.Pending, Delivery: h.service.EmailEnabled()})
}

// setAccountEmail sends a confirmation link to the new address; the account
// keeps its current address until the link is used.
func (h *authHTTP) setAccountEmail(response http.ResponseWriter, request *http.Request) {
	var payload struct {
		Email string `json:"email"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	// Same rule as adding a passkey: accounts with second factors need a
	// recent second-factor check.
	session, ok := h.passkeySession(response, request)
	if !ok {
		return
	}
	if err := h.service.RequestEmailVerification(request.Context(), session.UserID, payload.Email); err != nil {
		writeRecoveryError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, struct {
		Status string `json:"status"`
	}{"confirmation_sent"})
}

// confirmEmail uses the link from the confirmation email. It needs no
// session, so the link works on any device.
func (h *authHTTP) confirmEmail(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload struct {
		Token string `json:"token"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	if !h.beginInvitationAttempt(response, request) {
		return
	}
	if err := h.service.ConfirmEmail(request.Context(), payload.Token); err != nil {
		writeRecoveryError(response, err)
		return
	}
	h.completeInvitationAttempt(request)
	writeNoContent(response)
}
