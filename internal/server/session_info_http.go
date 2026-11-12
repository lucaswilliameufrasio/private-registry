package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/sessions"
)

func (h *authHTTP) registerSessionInfoRoutes(router chi.Router) {
	router.Get("/api/v1/auth/session", h.sessionInfo)
	router.Get("/api/v1/auth/methods", h.authMethods)
	router.Get("/api/v1/workspaces/{workspaceID}/members", h.listMembers)
}

// sessionInfo describes the current session for the web interface. Any
// session level answers, so the interface knows which step comes next.
func (h *authHTTP) sessionInfo(response http.ResponseWriter, request *http.Request) {
	bearer, found, err := uniqueCookie(request, sessionCookieName)
	if err != nil || !found {
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
		return
	}
	session, err := h.service.ValidateSession(request.Context(), bearer)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	result := struct {
		UserID        string `json:"user_id"`
		Level         string `json:"level"`
		MFARecent     bool   `json:"mfa_recent"`
		DisplayName   string `json:"display_name,omitempty"`
		LoginName     string `json:"login_name,omitempty"`
		InstanceAdmin bool   `json:"instance_admin"`
		HasTOTP       bool   `json:"has_totp"`
		Passkeys      int    `json:"passkeys"`
		MuiraEnabled  bool   `json:"muira_enabled"`
		ExpiresAt     string `json:"expires_at"`
	}{UserID: session.UserID, Level: string(session.Level), MuiraEnabled: h.service.MuiraEnabled(), ExpiresAt: session.IdleExpiresAt.Format(time.RFC3339Nano)}
	if session.Level == sessions.LevelMFA && session.MFAAuthenticatedAt != nil {
		age := time.Since(*session.MFAAuthenticatedAt)
		result.MFARecent = age >= 0 && age < workspaceCreationMFAMaxAge
	}
	if profile, err := h.workspaces.Profile(request.Context(), session.UserID); err == nil {
		result.DisplayName, result.LoginName, result.InstanceAdmin, result.HasTOTP, result.Passkeys = profile.DisplayName, profile.LoginName, profile.InstanceAdmin, profile.HasTOTP, profile.Passkeys
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *authHTTP) listMembers(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	members, err := h.workspaces.ListMembers(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"))
	if err != nil {
		writeWorkspaceError(response, err)
		return
	}
	type item struct {
		UserID         string `json:"user_id"`
		DisplayName    string `json:"display_name"`
		LoginName      string `json:"login_name,omitempty"`
		Role           string `json:"role"`
		ServiceAccount bool   `json:"service_account,omitempty"`
	}
	items := make([]item, 0, len(members))
	for _, member := range members {
		items = append(items, item{member.UserID, member.DisplayName, member.LoginName, member.Role, member.ServiceAccount})
	}
	writeJSON(response, http.StatusOK, struct {
		Members []item `json:"members"`
	}{items})
}

// authMethods tells the sign-in page which methods this installation offers.
func (h *authHTTP) authMethods(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, struct {
		Password      bool `json:"password"`
		Passkeys      bool `json:"passkeys"`
		Muira         bool `json:"muira"`
		EmailRecovery bool `json:"email_recovery"`
	}{true, h.service.PasskeysEnabled(), h.service.MuiraEnabled(), h.service.EmailEnabled()})
}
