package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/auth"
	"private-registry/internal/sessions"
)

const passkeyCookieName = "__Host-registry-passkey"

type passkeyResponse struct {
	PasskeyID  string `json:"passkey_id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

func (h *authHTTP) registerPasskeyRoutes(router chi.Router) {
	router.Post("/api/v1/auth/passkeys/registration/start", h.beginPasskeyRegistration)
	router.Post("/api/v1/auth/passkeys/registration/finish", h.finishPasskeyRegistration)
	router.Post("/api/v1/auth/passkeys/login/start", h.beginPasskeyLogin)
	router.Post("/api/v1/auth/passkeys/login/finish", h.finishPasskeyLogin)
	router.Get("/api/v1/auth/passkeys", h.listPasskeys)
	router.Delete("/api/v1/auth/passkeys/{passkeyID}", h.deletePasskey)
}

func writePasskeyError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrPasskeyRejected):
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
	case errors.Is(err, auth.ErrPasskeyLimit):
		writeAPIError(response, http.StatusConflict, "passkey_limit")
	case errors.Is(err, auth.ErrPasskeyUnknown):
		writeAPIError(response, http.StatusNotFound, "not_found")
	case errors.Is(err, auth.ErrPasskeysDisabled):
		writeAPIError(response, http.StatusNotFound, "not_found")
	default:
		writeServiceError(response, err)
	}
}

func setPasskeyCookie(response http.ResponseWriter, value string) {
	http.SetCookie(response, &http.Cookie{Name: passkeyCookieName, Value: value, Path: "/", MaxAge: int((5 * time.Minute).Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func clearPasskeyCookie(response http.ResponseWriter) {
	http.SetCookie(response, &http.Cookie{Name: passkeyCookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// passkeySession authorizes managing passkeys. Accounts that already have a
// second factor must have used it recently; accounts without one may add a
// passkey from a standard session, which then becomes their second factor.
func (h *authHTTP) passkeySession(response http.ResponseWriter, request *http.Request) (sessions.Session, bool) {
	if !h.requireCanonicalRequest(response, request) {
		return sessions.Session{}, false
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return sessions.Session{}, false
	}
	if session.Level == sessions.LevelStandard {
		return session, true
	}
	if !requireRecentMFA(response, session) {
		return sessions.Session{}, false
	}
	return session, true
}

func (h *authHTTP) beginPasskeyRegistration(response http.ResponseWriter, request *http.Request) {
	var payload struct {
		Name string `json:"name"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	session, ok := h.passkeySession(response, request)
	if !ok {
		return
	}
	options, sealed, err := h.service.BeginPasskeyRegistration(request.Context(), session.UserID, payload.Name)
	if err != nil {
		writePasskeyError(response, err)
		return
	}
	setPasskeyCookie(response, sealed)
	setAuthResponseHeaders(response)
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(options)
}

// finishPasskeyRegistration takes the browser's PublicKeyCredential JSON as
// the request body.
func (h *authHTTP) finishPasskeyRegistration(response http.ResponseWriter, request *http.Request) {
	session, ok := h.passkeySession(response, request)
	if !ok {
		return
	}
	sealed, found, err := uniqueCookie(request, passkeyCookieName)
	clearPasskeyCookie(response)
	if err != nil || !found {
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, 64<<10)
	passkey, err := h.service.FinishPasskeyRegistration(request.Context(), session.UserID, sealed, request)
	if err != nil {
		writePasskeyError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, passkeyResponse{PasskeyID: passkey.ID, Name: passkey.Name, CreatedAt: passkey.CreatedAt.Format(time.RFC3339Nano)})
}

func (h *authHTTP) beginPasskeyLogin(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	options, sealed, err := h.service.BeginPasskeyLogin(request.Context())
	if err != nil {
		writePasskeyError(response, err)
		return
	}
	setPasskeyCookie(response, sealed)
	setAuthResponseHeaders(response)
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(options)
}

func (h *authHTTP) finishPasskeyLogin(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	sealed, found, err := uniqueCookie(request, passkeyCookieName)
	clearPasskeyCookie(response)
	if err != nil || !found {
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
		return
	}
	if !h.beginInvitationAttempt(response, request) {
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, 64<<10)
	credentials, err := h.service.FinishPasskeyLogin(request.Context(), sealed, request)
	if err != nil {
		writePasskeyError(response, err)
		return
	}
	h.completeInvitationAttempt(request)
	setSessionCookies(response, credentials)
	writeJSON(response, http.StatusOK, loginResponse{Stage: string(auth.StageAuthenticated)})
}

func (h *authHTTP) listPasskeys(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	passkeys, err := h.service.ListPasskeys(request.Context(), session.UserID)
	if err != nil {
		writePasskeyError(response, err)
		return
	}
	items := make([]passkeyResponse, 0, len(passkeys))
	for _, passkey := range passkeys {
		item := passkeyResponse{PasskeyID: passkey.ID, Name: passkey.Name, CreatedAt: passkey.CreatedAt.Format(time.RFC3339Nano)}
		if passkey.LastUsedAt != nil {
			item.LastUsedAt = passkey.LastUsedAt.Format(time.RFC3339Nano)
		}
		items = append(items, item)
	}
	writeJSON(response, http.StatusOK, struct {
		Passkeys []passkeyResponse `json:"passkeys"`
	}{items})
}

func (h *authHTTP) deletePasskey(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	if err := h.service.DeletePasskey(request.Context(), actor, chi.URLParam(request, "passkeyID")); err != nil {
		writePasskeyError(response, err)
		return
	}
	writeNoContent(response)
}
