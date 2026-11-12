package server

import (
	"errors"
	"net/http"
	"strings"

	"private-registry/internal/auth"
)

const muiraStateCookieName = "__Host-registry-muira-state"

type muiraLinkStartResponse struct {
	AuthorizeURL string `json:"authorize_url"`
}

type muiraCompletionResponse struct {
	Stage string `json:"stage"`
}

type muiraProvisionRequest struct {
	Subject     string `json:"subject"`
	DisplayName string `json:"display_name"`
}

type muiraProvisionResponse struct {
	UserID string `json:"user_id"`
}

// registerMuiraRoutes is only called when the optional provider is enabled;
// otherwise these paths do not exist and local sign-in is the only method.
func (h *authHTTP) registerMuiraRoutes(router interface {
	Get(string, http.HandlerFunc)
	Post(string, http.HandlerFunc)
	Delete(string, http.HandlerFunc)
}) {
	router.Get("/api/v1/auth/muira/start", h.muiraStart)
	router.Get("/api/v1/auth/muira/callback", h.muiraCallback)
	router.Post("/api/v1/auth/muira/link", h.muiraLinkStart)
	router.Delete("/api/v1/auth/muira/link", h.muiraUnlink)
	router.Post("/api/v1/admin/muira/users", h.muiraProvisionUser)
}

// requireCanonicalNavigation validates a top-level browser navigation, which
// carries no Origin header: the request must target the canonical host over
// HTTPS and must not be a cross-origin subresource or script request.
func (h *authHTTP) requireCanonicalNavigation(response http.ResponseWriter, request *http.Request) bool {
	requestOrigin, err := normalizeOrigin("https://" + request.Host)
	if err != nil || requestOrigin != h.canonicalOrigin || !requestUsesHTTPS(request, h.trustedProxies) {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return false
	}
	if origins := request.Header.Values("Origin"); len(origins) > 0 {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return false
	}
	return true
}

func (h *authHTTP) muiraStart(response http.ResponseWriter, request *http.Request) {
	setAuthResponseHeaders(response)
	if !h.requireCanonicalNavigation(response, request) {
		return
	}
	if len(request.URL.RawQuery) != 0 {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	start, err := h.service.BeginMuiraLogin(request.Context())
	if err != nil {
		writeMuiraError(response, err)
		return
	}
	setMuiraStateCookie(response, start)
	response.Header().Set("Location", start.AuthorizeURL)
	response.WriteHeader(http.StatusFound)
}

func (h *authHTTP) muiraLinkStart(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	start, err := h.service.BeginMuiraLink(request.Context(), session.UserID)
	if err != nil {
		writeMuiraError(response, err)
		return
	}
	setMuiraStateCookie(response, start)
	writeJSON(response, http.StatusOK, muiraLinkStartResponse{AuthorizeURL: start.AuthorizeURL})
}

func (h *authHTTP) muiraCallback(response http.ResponseWriter, request *http.Request) {
	setAuthResponseHeaders(response)
	if !h.requireCanonicalNavigation(response, request) {
		return
	}
	sealedState, found, err := uniqueCookie(request, muiraStateCookieName)
	// The attempt is single use from the browser's point of view: the cookie
	// is cleared before anything else is decided.
	clearMuiraStateCookie(response)
	if err != nil || !found {
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
		return
	}
	query := request.URL.Query()
	if len(request.URL.RawQuery) > 8192 || len(query["state"]) != 1 {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if len(query["error"]) > 0 {
		// Provider-supplied descriptions are not reflected back.
		if browserNavigation(request) {
			redirectToInterface(response, "/#/login?error=muira")
			return
		}
		writeAPIError(response, http.StatusUnauthorized, "muira_authorization_denied")
		return
	}
	if len(query["code"]) != 1 {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	bearerToken, _, err := uniqueCookie(request, sessionCookieName)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	completion, err := h.service.CompleteMuira(request.Context(), sealedState, query.Get("state"), query.Get("code"), bearerToken)
	if err != nil {
		if browserNavigation(request) {
			redirectToInterface(response, "/#/login?error=muira")
			return
		}
		writeMuiraError(response, err)
		return
	}
	switch completion.Intent {
	case auth.MuiraIntentLink:
		if browserNavigation(request) {
			redirectToInterface(response, "/#/account?linked=muira")
			return
		}
		writeJSON(response, http.StatusOK, muiraCompletionResponse{Stage: "linked"})
	case auth.MuiraIntentLogin:
		result := completion.Result
		if result.Credentials.BearerToken == "" || result.Credentials.CSRFToken == "" {
			writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
		switch result.Stage {
		case auth.StageAuthenticated, auth.StageMFAChallenge, auth.StageMFAEnrollment:
		default:
			writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
		setSessionCookies(response, result.Credentials)
		if browserNavigation(request) {
			redirectToInterface(response, "/#/login?stage="+string(result.Stage))
			return
		}
		writeJSON(response, http.StatusOK, muiraCompletionResponse{Stage: string(result.Stage)})
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
	}
}

func (h *authHTTP) muiraUnlink(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	if err := h.service.UnlinkMuira(request.Context(), session.UserID); err != nil {
		if errors.Is(err, auth.ErrRejected) {
			writeAPIError(response, http.StatusNotFound, "not_found")
			return
		}
		writeMuiraError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) muiraProvisionUser(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload muiraProvisionRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	userID, err := h.service.ProvisionMuiraUser(request.Context(), session.UserID, payload.Subject, payload.DisplayName)
	if err != nil {
		writeMuiraError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, muiraProvisionResponse{UserID: userID})
}

func writeMuiraError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrMuiraConflict):
		writeAPIError(response, http.StatusConflict, "muira_identity_conflict")
	case errors.Is(err, auth.ErrMuiraInvalid):
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, auth.ErrMuiraForbidden):
		writeAPIError(response, http.StatusForbidden, "forbidden")
	case errors.Is(err, auth.ErrMuiraDisabled):
		writeAPIError(response, http.StatusNotFound, "not_found")
	default:
		writeServiceError(response, err)
	}
}

func setMuiraStateCookie(response http.ResponseWriter, start auth.MuiraStart) {
	// SameSite=Lax is required: the provider returns with a cross-site
	// top-level GET, which Strict would strip.
	http.SetCookie(response, &http.Cookie{
		Name:     muiraStateCookieName,
		Value:    start.SealedState,
		Path:     "/",
		MaxAge:   int(start.ExpiresIn.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearMuiraStateCookie(response http.ResponseWriter) {
	http.SetCookie(response, &http.Cookie{
		Name:     muiraStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// browserNavigation reports a top-level page load, as opposed to an API call,
// so the callback can send people back to the web interface.
func browserNavigation(request *http.Request) bool {
	return request.Header.Get("Sec-Fetch-Mode") == "navigate" || strings.Contains(request.Header.Get("Accept"), "text/html")
}

func redirectToInterface(response http.ResponseWriter, location string) {
	response.Header().Set("Location", location)
	response.WriteHeader(http.StatusSeeOther)
}
