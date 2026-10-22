package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/auth"
	"private-registry/internal/sessions"
)

const (
	maxAuthRequestBytes        = 8 << 10
	maxForwardedForHeaderBytes = 2048
	sessionCookieName          = "__Host-registry-session"
	csrfCookieName             = "__Host-registry-csrf"
	csrfHeaderName             = "X-CSRF-Token"
)

type AuthHTTPConfig struct {
	CanonicalOrigin string
	TrustedProxies  []netip.Prefix
}

type authHTTP struct {
	service         *auth.Service
	canonicalOrigin string
	trustedProxies  []netip.Prefix
}

type loginRequest struct {
	LoginName string `json:"login_name"`
	Password  string `json:"password"`
}

type codeRequest struct {
	Code string `json:"code"`
}

type loginResponse struct {
	Stage string `json:"stage"`
}

type enrollmentResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
	ExpiresAt  string `json:"expires_at"`
}

type enrollmentCompletionResponse struct {
	Stage         string   `json:"stage"`
	RecoveryCodes []string `json:"recovery_codes"`
}

type apiErrorResponse struct {
	Error string `json:"error"`
}

// NewHandler composes health probes with the narrow, public authentication
// routes. It deliberately registers no workspace, administrative, or content
// routes; those remain unavailable until authorization is implemented.
func NewHandler(health *Health, service *auth.Service, cfg AuthHTTPConfig) (http.Handler, error) {
	if health == nil || service == nil {
		return nil, errors.New("health and authentication services are required")
	}
	canonicalOrigin, err := normalizeOrigin(cfg.CanonicalOrigin)
	if err != nil {
		return nil, errors.New("a valid HTTPS canonical origin is required")
	}
	for _, proxy := range cfg.TrustedProxies {
		if !proxy.IsValid() {
			return nil, errors.New("trusted proxy configuration is invalid")
		}
	}

	router := chi.NewRouter()
	health.registerRoutes(router)
	authentication := &authHTTP{
		service:         service,
		canonicalOrigin: canonicalOrigin,
		trustedProxies:  append([]netip.Prefix(nil), cfg.TrustedProxies...),
	}
	authentication.registerRoutes(router)
	return router, nil
}

func (h *authHTTP) registerRoutes(router chi.Router) {
	router.Post("/api/v1/auth/login", h.login)
	router.Post("/api/v1/auth/mfa/enrollment", h.beginMFAEnrollment)
	router.Post("/api/v1/auth/mfa/enrollment/complete", h.completeMFAEnrollment)
	router.Post("/api/v1/auth/mfa/challenge", h.completeMFAChallenge)
	router.Post("/api/v1/auth/logout", h.logout)
}

func (h *authHTTP) login(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload loginRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	sourceAddress, err := clientAddress(request, h.trustedProxies)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	passwordValue := []byte(payload.Password)
	defer clear(passwordValue)

	result, err := h.service.Login(request.Context(), payload.LoginName, passwordValue, sourceAddress)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	if result.Credentials.BearerToken == "" || result.Credentials.CSRFToken == "" {
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	stage := string(result.Stage)
	switch result.Stage {
	case auth.StageAuthenticated, auth.StageMFAChallenge, auth.StageMFAEnrollment:
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	setSessionCookies(response, result.Credentials)
	writeJSON(response, http.StatusOK, loginResponse{Stage: stage})
}

func (h *authHTTP) beginMFAEnrollment(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	bearerToken, _, ok := h.validateBrowserSession(response, request)
	if !ok {
		return
	}
	enrollment, err := h.service.BeginMFAEnrollment(request.Context(), bearerToken)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, enrollmentResponse{
		Secret:     enrollment.Secret,
		OTPAuthURL: enrollment.OTPAuthURL,
		ExpiresAt:  enrollment.ExpiresAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	})
}

func (h *authHTTP) completeMFAEnrollment(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload codeRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	bearerToken, _, ok := h.validateBrowserSession(response, request)
	if !ok {
		return
	}
	sourceAddress, err := clientAddress(request, h.trustedProxies)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	completion, err := h.service.CompleteMFAEnrollment(
		request.Context(), bearerToken, payload.Code, sourceAddress)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	if completion.Credentials.BearerToken == "" || completion.Credentials.CSRFToken == "" ||
		len(completion.RecoveryCodes) != 10 {
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	setSessionCookies(response, completion.Credentials)
	writeJSON(response, http.StatusOK, enrollmentCompletionResponse{
		Stage:         string(auth.StageAuthenticated),
		RecoveryCodes: completion.RecoveryCodes,
	})
}

func (h *authHTTP) completeMFAChallenge(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload codeRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	bearerToken, _, ok := h.validateBrowserSession(response, request)
	if !ok {
		return
	}
	sourceAddress, err := clientAddress(request, h.trustedProxies)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	credentials, err := h.service.CompleteMFA(request.Context(), bearerToken, payload.Code, sourceAddress)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	if credentials.BearerToken == "" || credentials.CSRFToken == "" {
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	setSessionCookies(response, credentials)
	writeJSON(response, http.StatusOK, loginResponse{Stage: string(auth.StageAuthenticated)})
}

func (h *authHTTP) logout(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	bearerToken, found, err := uniqueCookie(request, sessionCookieName)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if !found {
		clearSessionCookies(response)
		writeNoContent(response)
		return
	}
	csrfToken, csrfFound, err := uniqueCookie(request, csrfCookieName)
	if err != nil || !csrfFound || !requestCSRFHeaderMatches(request, csrfToken) {
		writeAPIError(response, http.StatusForbidden, "csrf_failed")
		return
	}
	_, validationErr := h.service.ValidateWithCSRF(request.Context(), bearerToken, csrfToken)
	if validationErr != nil && !errors.Is(validationErr, sessions.ErrSessionUnavailable) {
		writeServiceError(response, validationErr)
		return
	}
	if err := h.service.Logout(request.Context(), bearerToken); err != nil {
		writeServiceError(response, err)
		return
	}
	clearSessionCookies(response)
	writeNoContent(response)
}

func (h *authHTTP) validateBrowserSession(
	response http.ResponseWriter,
	request *http.Request,
) (string, string, bool) {
	bearerToken, found, err := uniqueCookie(request, sessionCookieName)
	if err != nil || !found {
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
		return "", "", false
	}
	csrfToken, found, err := uniqueCookie(request, csrfCookieName)
	if err != nil || !found || !requestCSRFHeaderMatches(request, csrfToken) {
		writeAPIError(response, http.StatusForbidden, "csrf_failed")
		return "", "", false
	}
	if _, err := h.service.ValidateWithCSRF(request.Context(), bearerToken, csrfToken); err != nil {
		writeServiceError(response, err)
		return "", "", false
	}
	return bearerToken, csrfToken, true
}

func (h *authHTTP) requireCanonicalRequest(response http.ResponseWriter, request *http.Request) bool {
	originValues := request.Header.Values("Origin")
	if len(originValues) != 1 {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return false
	}
	origin, err := normalizeOrigin(originValues[0])
	if err != nil || origin != h.canonicalOrigin {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return false
	}
	requestOrigin, err := normalizeOrigin("https://" + request.Host)
	if err != nil || requestOrigin != h.canonicalOrigin {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return false
	}
	if !requestUsesHTTPS(request, h.trustedProxies) {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return false
	}
	return true
}

func requestUsesHTTPS(request *http.Request, trustedProxies []netip.Prefix) bool {
	if request.TLS != nil {
		return true
	}
	peer, err := parseAddressWithOptionalPort(request.RemoteAddr)
	if err != nil || !isTrustedProxy(peer, trustedProxies) {
		return false
	}
	forwardedProtocols := request.Header.Values("X-Forwarded-Proto")
	return len(forwardedProtocols) == 1 && strings.EqualFold(strings.TrimSpace(forwardedProtocols[0]), "https")
}

func decodeJSONBody[T any](response http.ResponseWriter, request *http.Request, destination *T) int {
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return http.StatusUnsupportedMediaType
	}
	if charset, exists := parameters["charset"]; exists && !strings.EqualFold(charset, "utf-8") {
		return http.StatusUnsupportedMediaType
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxAuthRequestBytes))
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return http.StatusRequestEntityTooLarge
		}
		return http.StatusBadRequest
	}
	trimmedBody := bytes.TrimSpace(body)
	if len(trimmedBody) == 0 || trimmedBody[0] != '{' || !hasUniqueJSONKeys(trimmedBody) {
		return http.StatusBadRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmedBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return http.StatusBadRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return http.StatusBadRequest
	}
	return 0
}

func hasUniqueJSONKeys(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return false
		}
		key, ok := keyToken.(string)
		if !ok {
			return false
		}
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
	}
	closingToken, err := decoder.Token()
	if err != nil || closingToken != json.Delim('}') {
		return false
	}
	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}

func requestErrorCode(status int) string {
	if status == http.StatusUnsupportedMediaType {
		return "unsupported_media_type"
	}
	if status == http.StatusRequestEntityTooLarge {
		return "request_too_large"
	}
	return "invalid_request"
}

func writeServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrRejected), errors.Is(err, sessions.ErrSessionUnavailable):
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
	case errors.Is(err, auth.ErrRateLimited):
		writeAPIError(response, http.StatusTooManyRequests, "rate_limited")
	case errors.Is(err, sessions.ErrCSRF):
		writeAPIError(response, http.StatusForbidden, "csrf_failed")
	case errors.Is(err, auth.ErrInvalidClientAddress):
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, auth.ErrEnrollmentUnavailable):
		writeAPIError(response, http.StatusConflict, "mfa_enrollment_unavailable")
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
	}
}

func writeAPIError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, apiErrorResponse{Error: code})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	setAuthResponseHeaders(response)
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		return
	}
}

func writeNoContent(response http.ResponseWriter) {
	setAuthResponseHeaders(response)
	response.WriteHeader(http.StatusNoContent)
}

func setAuthResponseHeaders(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
}

func setSessionCookies(response http.ResponseWriter, credentials sessions.Credentials) {
	http.SetCookie(response, &http.Cookie{
		Name:     sessionCookieName,
		Value:    credentials.BearerToken,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(response, &http.Cookie{
		Name:     csrfCookieName,
		Value:    credentials.CSRFToken,
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookies(response http.ResponseWriter) {
	http.SetCookie(response, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(response, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func uniqueCookie(request *http.Request, name string) (string, bool, error) {
	value := ""
	found := false
	for _, cookie := range request.Cookies() {
		if cookie.Name != name {
			continue
		}
		if found {
			return "", false, errors.New("duplicate authentication cookie")
		}
		found = true
		value = cookie.Value
	}
	if !found || value == "" {
		return "", found, nil
	}
	return value, true, nil
}

func requestCSRFHeaderMatches(request *http.Request, cookieValue string) bool {
	values := request.Header.Values(csrfHeaderName)
	if len(values) != 1 || values[0] == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(values[0]), []byte(cookieValue)) == 1
}

func normalizeOrigin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || strings.ContainsAny(raw, "?#") || !strings.EqualFold(parsed.Scheme, "https") {
		return "", errors.New("origin must be an HTTPS origin without a path")
	}
	if strings.HasSuffix(parsed.Host, ":") || strings.Contains(parsed.Host, "%") {
		return "", errors.New("origin authority is invalid")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", errors.New("origin host is invalid")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address.Zone() != "" {
			return "", errors.New("origin host zone is not supported")
		}
		host = address.String()
	} else if !validDNSHost(host) {
		return "", errors.New("origin host is invalid")
	}

	portValue := parsed.Port()
	if portValue == "" {
		if strings.Contains(host, ":") {
			return "https://[" + host + "]", nil
		}
		return "https://" + host, nil
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("origin port is invalid")
	}
	if port == 443 {
		if strings.Contains(host, ":") {
			return "https://[" + host + "]", nil
		}
		return "https://" + host, nil
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func validDNSHost(host string) bool {
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func clientAddress(request *http.Request, trustedProxies []netip.Prefix) (string, error) {
	peer, err := parseAddressWithOptionalPort(request.RemoteAddr)
	if err != nil {
		return "", errors.New("peer network address is invalid")
	}
	if !isTrustedProxy(peer, trustedProxies) {
		return peer.String(), nil
	}
	forwardedValues := request.Header.Values("X-Forwarded-For")
	if len(forwardedValues) == 0 {
		return peer.String(), nil
	}
	forwardedHeader := strings.Join(forwardedValues, ",")
	if len(forwardedHeader) > maxForwardedForHeaderBytes {
		return "", errors.New("forwarded address chain is too long")
	}
	forwarded := strings.Split(forwardedHeader, ",")
	if len(forwarded) > 16 {
		return "", errors.New("forwarded address chain is too long")
	}
	addresses := make([]netip.Addr, 0, len(forwarded))
	for _, value := range forwarded {
		address, err := parseAddressWithOptionalPort(strings.TrimSpace(value))
		if err != nil {
			return "", errors.New("forwarded address chain is invalid")
		}
		addresses = append(addresses, address)
	}
	client := peer
	for index := len(addresses) - 1; index >= 0; index-- {
		if !isTrustedProxy(client, trustedProxies) {
			break
		}
		client = addresses[index]
	}
	return client.String(), nil
}

func parseAddressWithOptionalPort(value string) (netip.Addr, error) {
	if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
		return address.Unmap(), nil
	}
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("network address is invalid: %w", err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, errors.New("network address is invalid")
	}
	return address.Unmap(), nil
}

func isTrustedProxy(address netip.Addr, trustedProxies []netip.Prefix) bool {
	for _, proxy := range trustedProxies {
		if proxy.Contains(address) {
			return true
		}
	}
	return false
}
