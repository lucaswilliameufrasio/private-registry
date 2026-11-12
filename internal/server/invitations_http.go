package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/workspaces"
)

type signupPolicyBody struct {
	Policy string `json:"policy"`
}

type invitationCreateRequest struct {
	Role       string `json:"role"`
	TTLSeconds int64  `json:"ttl_seconds"`
	// Email, when set, sends the invitation to this address.
	Email string `json:"email"`
}

type invitationResponse struct {
	InvitationID string `json:"invitation_id"`
	Role         string `json:"role"`
	State        string `json:"state,omitempty"`
	CreatedBy    string `json:"created_by,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	ExpiresAt    string `json:"expires_at"`
	Email        string `json:"email,omitempty"`
	// Token is present only in the creation response of an invitation that
	// was not emailed.
	Token string `json:"token,omitempty"`
}

type invitationListResponse struct {
	Invitations []invitationResponse `json:"invitations"`
}

type invitationTokenRequest struct {
	Token string `json:"token"`
}

type invitationRedeemRequest struct {
	Token       string `json:"token"`
	LoginName   string `json:"login_name"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

type invitationAcceptedResponse struct {
	WorkspaceID string `json:"workspace_id"`
	UserID      string `json:"user_id,omitempty"`
}

func (h *authHTTP) registerInvitationRoutes(router chi.Router) {
	router.Get("/api/v1/admin/signup-policy", h.getSignupPolicy)
	router.Put("/api/v1/admin/signup-policy", h.setSignupPolicy)
	router.Post("/api/v1/workspaces/{workspaceID}/invitations", h.createInvitation)
	router.Get("/api/v1/workspaces/{workspaceID}/invitations", h.listInvitations)
	router.Delete("/api/v1/workspaces/{workspaceID}/invitations/{invitationID}", h.revokeInvitation)
	router.Post("/api/v1/invitations/accept", h.acceptInvitation)
	router.Post("/api/v1/auth/invitations/redeem", h.redeemInvitation)
}

func writeInvitationError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, workspaces.ErrInvitationUnavailable):
		writeAPIError(response, http.StatusNotFound, "invitation_unavailable")
	case errors.Is(err, workspaces.ErrSignupClosed):
		writeAPIError(response, http.StatusForbidden, "signup_closed")
	case errors.Is(err, workspaces.ErrLoginNameTaken):
		writeAPIError(response, http.StatusConflict, "login_name_taken")
	case errors.Is(err, workspaces.ErrAlreadyMember):
		writeAPIError(response, http.StatusConflict, "already_member")
	case errors.Is(err, workspaces.ErrMembershipUnavailable):
		writeAPIError(response, http.StatusConflict, "membership_unavailable")
	case errors.Is(err, workspaces.ErrEmailUnavailable):
		writeAPIError(response, http.StatusConflict, "email_unavailable")
	case errors.Is(err, workspaces.ErrInvalidAccount), errors.Is(err, workspaces.ErrInvalidInvitation), errors.Is(err, workspaces.ErrInvalidPolicy):
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
	default:
		writeWorkspaceError(response, err)
	}
}

func (h *authHTTP) getSignupPolicy(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	policy, err := h.workspaces.SignupPolicyValue(request.Context(), session.UserID)
	if err != nil {
		writeInvitationError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, signupPolicyBody{Policy: string(policy)})
}

func (h *authHTTP) setSignupPolicy(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload signupPolicyBody
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return
	}
	if err := h.workspaces.SetSignupPolicy(request.Context(), session.UserID, workspaces.SignupPolicy(payload.Policy)); err != nil {
		writeInvitationError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) createInvitation(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload invitationCreateRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return
	}
	if payload.TTLSeconds < 0 || payload.TTLSeconds > int64((30*24*time.Hour)/time.Second) {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	issued, err := h.workspaces.CreateInvitationFor(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), payload.Role, time.Duration(payload.TTLSeconds)*time.Second, payload.Email)
	if err != nil {
		writeInvitationError(response, err)
		return
	}
	result := invitationResponse{InvitationID: issued.ID, Role: issued.Role, ExpiresAt: issued.ExpiresAt.Format(time.RFC3339Nano), Email: strings.TrimSpace(payload.Email), Token: issued.Token}
	// An emailed link goes only to its recipient.
	if result.Email != "" {
		result.Token = ""
	}
	writeJSON(response, http.StatusCreated, result)
}

func (h *authHTTP) listInvitations(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	items, err := h.workspaces.ListInvitations(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"))
	if err != nil {
		writeInvitationError(response, err)
		return
	}
	result := invitationListResponse{Invitations: make([]invitationResponse, 0, len(items))}
	for _, item := range items {
		result.Invitations = append(result.Invitations, invitationResponse{InvitationID: item.ID, Role: item.Role, State: item.State, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt.Format(time.RFC3339Nano), ExpiresAt: item.ExpiresAt.Format(time.RFC3339Nano), Email: item.Email})
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *authHTTP) revokeInvitation(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return
	}
	if err := h.workspaces.RevokeInvitation(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "invitationID")); err != nil {
		writeInvitationError(response, err)
		return
	}
	writeNoContent(response)
}

// acceptInvitation joins the signed-in account, including accounts that
// sign in through Muira, to the invitation's workspace.
func (h *authHTTP) acceptInvitation(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload invitationTokenRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !h.beginInvitationAttempt(response, request) {
		return
	}
	workspaceID, err := h.workspaces.AcceptInvitation(request.Context(), session.UserID, payload.Token)
	if err != nil {
		writeInvitationError(response, err)
		return
	}
	h.completeInvitationAttempt(request)
	writeJSON(response, http.StatusOK, invitationAcceptedResponse{WorkspaceID: workspaceID})
}

// redeemInvitation creates a local account. It does not sign the account in:
// the new user logs in normally, which applies the MFA policy.
func (h *authHTTP) redeemInvitation(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload invitationRedeemRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	passwordValue := []byte(payload.Password)
	defer clear(passwordValue)
	if !h.beginInvitationAttempt(response, request) {
		return
	}
	select {
	case h.invitationHashSlots <- struct{}{}:
		defer func() { <-h.invitationHashSlots }()
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	userID, workspaceID, err := h.workspaces.RedeemInvitation(request.Context(), payload.Token, payload.LoginName, payload.DisplayName, passwordValue)
	if err != nil {
		writeInvitationError(response, err)
		return
	}
	h.completeInvitationAttempt(request)
	writeJSON(response, http.StatusCreated, invitationAcceptedResponse{WorkspaceID: workspaceID, UserID: userID})
}

// Invitation tokens share the bounded per-source budget of personal tokens:
// failures count, success clears the source.
func (h *authHTTP) beginInvitationAttempt(response http.ResponseWriter, request *http.Request) bool {
	source, err := clientAddress(request, h.trustedProxies)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return false
	}
	if _, err := h.service.BeginPersonalToken(request.Context(), source); err != nil {
		writeServiceError(response, err)
		return false
	}
	return true
}

func (h *authHTTP) completeInvitationAttempt(request *http.Request) {
	if source, err := clientAddress(request, h.trustedProxies); err == nil {
		_ = h.service.CompletePersonalToken(request.Context(), source)
	}
}
