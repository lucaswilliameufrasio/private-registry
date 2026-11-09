package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/mod/semver"
	"private-registry/internal/pub"
	"private-registry/internal/repositories"
)

// Pub read routes are experimental and explicitly opt-in. They do not expose
// native publication and are not wired into the production server.
func (h *authHTTP) registerPubReadRoutes(router chi.Router) {
	base := "/pub/{workspaceID}/{repositoryID}"
	router.Get(base+"/api/packages/{name}", h.pubMetadata)
	router.Get(base+"/packages/{name}/{archive}", h.pubArchive)
}

func pubProtocolError(response http.ResponseWriter, status int, code, message string) {
	npmReadJSON(response, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func (h *authHTTP) pubMetadata(response http.ResponseWriter, request *http.Request) {
	workspace, repository, ok := h.npmReadScope(response, request)
	if !ok {
		return
	}
	var token string
	if strings.HasPrefix(request.Header.Get("Authorization"), "Bearer prpw_") {
		token, ok = h.pubWriteCredential(response, request, workspace, repository)
	} else {
		token, ok = h.npmReadCredential(response, request, workspace, repository)
	}
	if !ok {
		return
	}
	name := chi.URLParam(request, "name")
	if strings.Contains(strings.ToLower(request.URL.EscapedPath()), "%25") || pub.ValidateName(name) != nil {
		pubProtocolError(response, http.StatusNotFound, "PACKAGE_NOT_FOUND", "package unavailable")
		return
	}
	select {
	case h.pubMetadataSlots <- struct{}{}:
		defer func() { <-h.pubMetadataSlots }()
	default:
		pubProtocolError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "metadata capacity unavailable")
		return
	}
	request, cancel, ok := goRequestContext(response, request, false)
	if !ok {
		return
	}
	defer cancel()
	versions, err := h.pubReservations.ReadPublishedVersionsWithToken(request.Context(), token, workspace, repository, name)
	if err != nil {
		writePubReadError(response, err)
		return
	}
	type metadata struct {
		Version       string          `json:"version"`
		ArchiveURL    string          `json:"archive_url"`
		ArchiveSHA256 string          `json:"archive_sha256"`
		Pubspec       json.RawMessage `json:"pubspec"`
	}
	items := make([]metadata, 0, len(versions))
	latest := 0
	for _, item := range versions {
		manifest, err := pub.PubspecJSON(item.Manifest, name, item.Version)
		if err != nil {
			pubProtocolError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "package metadata unavailable")
			return
		}
		archiveURL := h.canonicalOrigin + "/pub/" + workspace + "/" + repository + "/packages/" + url.PathEscape(name) + "/" + url.PathEscape(item.Version) + ".tar.gz"
		items = append(items, metadata{Version: item.Version, ArchiveURL: archiveURL, ArchiveSHA256: item.SHA256, Pubspec: manifest})
		if semver.Compare("v"+item.Version, "v"+items[latest].Version) > 0 {
			latest = len(items) - 1
		}
	}
	encoded, err := json.Marshal(struct {
		Name     string     `json:"name"`
		Latest   metadata   `json:"latest"`
		Versions []metadata `json:"versions"`
	}{Name: name, Latest: items[latest], Versions: items})
	if err != nil || len(encoded) > 20<<20 {
		pubProtocolError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "package metadata unavailable")
		return
	}
	setAuthResponseHeaders(response)
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("Vary", "Authorization")
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encoded)
}

func (h *authHTTP) pubArchive(response http.ResponseWriter, request *http.Request) {
	workspace, repository, ok := h.npmReadScope(response, request)
	if !ok {
		return
	}
	token, ok := h.npmReadCredential(response, request, workspace, repository)
	if !ok {
		return
	}
	name, archive := chi.URLParam(request, "name"), chi.URLParam(request, "archive")
	if strings.Contains(strings.ToLower(request.URL.EscapedPath()), "%25") || pub.ValidateName(name) != nil || !strings.HasSuffix(archive, ".tar.gz") {
		pubProtocolError(response, http.StatusNotFound, "ARCHIVE_NOT_FOUND", "archive unavailable")
		return
	}
	version, err := url.PathUnescape(strings.TrimSuffix(archive, ".tar.gz"))
	if err != nil {
		pubProtocolError(response, http.StatusNotFound, "ARCHIVE_NOT_FOUND", "archive unavailable")
		return
	}
	if err := http.NewResponseController(response).SetWriteDeadline(time.Now().Add(goRequestTimeout)); err != nil {
		pubProtocolError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "registry temporarily unavailable")
		return
	}
	defer func() { _ = http.NewResponseController(response).SetWriteDeadline(time.Time{}) }()
	request, cancel, ok := goRequestContext(response, request, false)
	if !ok {
		return
	}
	defer cancel()
	reader, size, err := h.pubReceipts.OpenPublishedArchiveWithToken(request.Context(), token, workspace, repository, name, version)
	if err != nil {
		writePubReadError(response, err)
		return
	}
	defer reader.Close()
	setAuthResponseHeaders(response)
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("Vary", "Authorization")
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	response.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(response, reader, size)
}

func writePubReadError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repositories.ErrPersonalTokenUnavailable):
		pubProtocolError(response, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "authentication required")
	case errors.Is(err, repositories.ErrForbidden):
		pubProtocolError(response, http.StatusForbidden, "PERMISSION_DENIED", "reader grant required")
	case errors.Is(err, pub.ErrPackageUnavailable):
		pubProtocolError(response, http.StatusNotFound, "PACKAGE_NOT_FOUND", "package unavailable")
	default:
		pubProtocolError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "registry temporarily unavailable")
	}
}
