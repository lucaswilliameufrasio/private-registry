package server

import (
	"database/sql"
	"errors"
	"net/http"
	"private-registry/internal/authattempts"
	"private-registry/internal/repositories"
	"strconv"
	"strings"
	"time"
)

func (h *authHTTP) pubWriteCredential(response http.ResponseWriter, request *http.Request, workspace, repository string) (string, bool) {
	select {
	case h.personalTokenSlots <- struct{}{}:
		defer func() { <-h.personalTokenSlots }()
	default:
		npmReadError(response, http.StatusServiceUnavailable, "registry temporarily unavailable")
		return "", false
	}
	source, err := clientAddress(request, h.trustedProxies)
	if err != nil {
		npmReadError(response, http.StatusBadRequest, "invalid request")
		return "", false
	}
	retryAfter, err := h.service.BeginPersonalToken(request.Context(), source)
	if err != nil {
		if errors.Is(err, authattempts.ErrRateLimited) {
			seconds := int64((retryAfter + time.Second - 1) / time.Second)
			if seconds < 1 {
				seconds = 1
			}
			response.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
			npmReadError(response, http.StatusTooManyRequests, "rate limited")
		} else {
			npmReadError(response, http.StatusServiceUnavailable, "registry temporarily unavailable")
		}
		return "", false
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || len(values[0]) > 135 {
		npmReadError(response, http.StatusUnauthorized, "authentication required")
		return "", false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, " \t\r\n") {
		npmReadError(response, http.StatusUnauthorized, "authentication required")
		return "", false
	}
	err = h.repositories.WithPubWriteTokenTransaction(request.Context(), token, workspace, repository, func(_ *sql.Tx, _ string) error { return nil })
	if errors.Is(err, repositories.ErrPubWriteTokenUnavailable) {
		npmReadError(response, http.StatusUnauthorized, "authentication required")
		return "", false
	} else if err != nil || h.service.CompletePersonalToken(request.Context(), source) != nil {
		npmReadError(response, http.StatusServiceUnavailable, "registry temporarily unavailable")
		return "", false
	}
	return token, true
}
