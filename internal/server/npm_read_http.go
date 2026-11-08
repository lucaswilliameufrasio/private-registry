package server

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"private-registry/internal/authattempts"
	"private-registry/internal/npm"
	"private-registry/internal/repositories"
)

// These routes are deliberately opt-in and read-only. Production wiring and
// native npm publication remain closed until all acceptance gates are met.
func (h *authHTTP) registerNPMReadRoutes(router chi.Router) {
	base := "/npm/{workspaceID}/{repositoryID}"
	router.Get(base+"/-/tarballs/{encodedName}/{version}", h.npmTarball)
	router.Get(base+"/*", h.npmPackument)
}

func npmReadError(response http.ResponseWriter, status int, message string) {
	npmReadJSON(response, status, map[string]string{"error": message})
}

func npmReadJSON(response http.ResponseWriter, status int, value any) {
	setAuthResponseHeaders(response)
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Vary", "Authorization")
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func (h *authHTTP) npmReadScope(response http.ResponseWriter, request *http.Request) (string, string, bool) {
	origin, err := normalizeOrigin("https://" + request.Host)
	workspace, repository := chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID")
	wid, werr := uuid.Parse(workspace)
	rid, rerr := uuid.Parse(repository)
	if err != nil || origin != h.canonicalOrigin || !requestUsesHTTPS(request, h.trustedProxies) || request.URL.RawQuery != "" || werr != nil || rerr != nil || wid == uuid.Nil || rid == uuid.Nil || wid.String() != workspace || rid.String() != repository {
		npmReadError(response, http.StatusForbidden, "registry unavailable")
		return "", "", false
	}
	return workspace, repository, true
}

func (h *authHTTP) npmReadCredential(response http.ResponseWriter, request *http.Request, workspace, repository string) (string, bool) {
	return h.npmCredential(response, request, workspace, repository, false)
}

func (h *authHTTP) npmCredential(response http.ResponseWriter, request *http.Request, workspace, repository string, write bool) (string, bool) {
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
	if write {
		err = h.repositories.WithNPMWriteTokenTransaction(request.Context(), token, workspace, repository, func(_ *sql.Tx, _ string) error { return nil })
	} else {
		_, err = h.repositories.VerifyPersonalReadToken(request.Context(), token, workspace, repository)
	}
	if errors.Is(err, repositories.ErrPersonalTokenUnavailable) || errors.Is(err, repositories.ErrNPMWriteTokenUnavailable) {
		npmReadError(response, http.StatusUnauthorized, "authentication required")
		return "", false
	} else if err != nil || h.service.CompletePersonalToken(request.Context(), source) != nil {
		npmReadError(response, http.StatusServiceUnavailable, "registry temporarily unavailable")
		return "", false
	}
	return token, true
}

func (h *authHTTP) npmPackument(response http.ResponseWriter, request *http.Request) {
	workspace, repository, ok := h.npmReadScope(response, request)
	if !ok {
		return
	}
	token, ok := h.npmReadCredential(response, request, workspace, repository)
	if !ok {
		return
	}
	if strings.Contains(strings.ToLower(request.URL.EscapedPath()), "%25") {
		npmReadError(response, http.StatusNotFound, "package unavailable")
		return
	}
	name, err := url.PathUnescape(chi.URLParam(request, "*"))
	if err != nil || npm.ValidatePackageName(name) != nil {
		npmReadError(response, http.StatusNotFound, "package unavailable")
		return
	}
	select {
	case h.npmMetadataSlots <- struct{}{}:
		defer func() { <-h.npmMetadataSlots }()
	default:
		npmReadError(response, http.StatusServiceUnavailable, "metadata capacity unavailable")
		return
	}
	request, cancel, ok := goRequestContext(response, request, false)
	if !ok {
		return
	}
	defer cancel()
	data, err := h.npmReservations.ReadPublishedPackageWithToken(request.Context(), token, workspace, repository, name)
	if err != nil {
		h.writeNPMReadError(response, err)
		return
	}
	versions := make(map[string]json.RawMessage, len(data.Versions))
	encodedName := base64.RawURLEncoding.EncodeToString([]byte(name))
	for _, item := range data.Versions {
		var manifest map[string]json.RawMessage
		if err := json.Unmarshal(item.Manifest, &manifest); err != nil || manifest == nil {
			npmReadError(response, http.StatusServiceUnavailable, "package metadata unavailable")
			return
		}
		tarball := h.canonicalOrigin + "/npm/" + workspace + "/" + repository + "/-/tarballs/" + encodedName + "/" + item.Version
		dist, err := json.Marshal(map[string]string{"integrity": item.Integrity, "tarball": tarball})
		if err != nil {
			npmReadError(response, http.StatusServiceUnavailable, "package metadata unavailable")
			return
		}
		manifest["dist"] = dist
		encoded, err := json.Marshal(manifest)
		if err != nil {
			npmReadError(response, http.StatusServiceUnavailable, "package metadata unavailable")
			return
		}
		versions[item.Version] = encoded
	}
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Vary", "Authorization")
	npmReadJSON(response, http.StatusOK, map[string]any{"name": data.Name, "versions": versions, "dist-tags": data.Tags})
}

func (h *authHTTP) npmTarball(response http.ResponseWriter, request *http.Request) {
	workspace, repository, ok := h.npmReadScope(response, request)
	if !ok {
		return
	}
	token, ok := h.npmReadCredential(response, request, workspace, repository)
	if !ok {
		return
	}
	encoded := chi.URLParam(request, "encodedName")
	nameBytes, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(nameBytes) > 214 || base64.RawURLEncoding.EncodeToString(nameBytes) != encoded {
		npmReadError(response, http.StatusNotFound, "package unavailable")
		return
	}
	deadline := time.Now().Add(goRequestTimeout)
	if err := http.NewResponseController(response).SetWriteDeadline(deadline); err != nil {
		npmReadError(response, http.StatusServiceUnavailable, "registry temporarily unavailable")
		return
	}
	defer func() { _ = http.NewResponseController(response).SetWriteDeadline(time.Time{}) }()
	request, cancel, ok := goRequestContext(response, request, false)
	if !ok {
		return
	}
	defer cancel()
	reader, size, err := h.npmReceipts.OpenPublishedArchiveWithToken(request.Context(), token, workspace, repository, string(nameBytes), chi.URLParam(request, "version"))
	if err != nil {
		h.writeNPMReadError(response, err)
		return
	}
	defer reader.Close()
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Vary", "Authorization")
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	response.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(response, reader, size)
}

func (h *authHTTP) writeNPMReadError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repositories.ErrPersonalTokenUnavailable):
		npmReadError(response, http.StatusUnauthorized, "authentication required")
	case errors.Is(err, npm.ErrPackageUnavailable):
		npmReadError(response, http.StatusNotFound, "package unavailable")
	default:
		npmReadError(response, http.StatusServiceUnavailable, "registry temporarily unavailable")
	}
}
