package server

import (
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

func (h *authHTTP) downloadPublicArtifact(response http.ResponseWriter, request *http.Request) {
	if !h.requireAssetRequest(response, request) {
		return
	}
	workspace := chi.URLParam(request, "workspaceSlug")
	repository := chi.URLParam(request, "repositorySlug")
	collection := chi.URLParam(request, "collection")
	version := chi.URLParam(request, "version")
	filePath := chi.URLParam(request, "*")
	file, err := h.artifacts.ResolvePublicFile(request.Context(), workspace, repository, collection, version, filePath)
	if err != nil {
		writeArtifactError(response, err)
		return
	}
	response.Header().Add("Vary", "Origin")
	origin, allowed := h.publicAssetCORSOrigin(request)
	if request.Method == http.MethodOptions {
		response.Header().Add("Vary", "Access-Control-Request-Method")
		response.Header().Add("Vary", "Access-Control-Request-Headers")
		if !allowed || !validPublicAssetPreflight(request) {
			writeAPIError(response, http.StatusForbidden, "cors_rejected")
			return
		}
		response.Header().Set("Access-Control-Allow-Origin", origin)
		response.Header().Set("Access-Control-Allow-Methods", "GET, HEAD")
		response.Header().Set("Access-Control-Allow-Headers", "Range, If-Range, If-None-Match")
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusNoContent)
		return
	}
	if allowed {
		response.Header().Set("Access-Control-Allow-Origin", origin)
		response.Header().Set("Access-Control-Expose-Headers", "ETag, Accept-Ranges, Content-Range")
	}
	etag := `"` + file.SHA256 + `"`
	response.Header().Set("Content-Type", file.ContentType)
	response.Header().Set("Content-Disposition", mime.FormatMediaType("inline", map[string]string{"filename": path.Base(file.Path)}))
	response.Header().Set("Content-Length", strconv.FormatInt(file.Size, 10))
	response.Header().Set("ETag", etag)
	response.Header().Set("Accept-Ranges", "bytes")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	response.Header().Set("X-Frame-Options", "DENY")
	if matchesETag(request.Header.Values("If-None-Match"), etag) {
		response.WriteHeader(http.StatusNotModified)
		return
	}
	rangeHeader := ""
	ifRangeValues := request.Header.Values("If-Range")
	if len(ifRangeValues) == 0 || (len(ifRangeValues) == 1 && strings.TrimSpace(ifRangeValues[0]) == etag) {
		rangeValues := request.Header.Values("Range")
		if len(rangeValues) > 1 {
			response.Header().Del("Content-Length")
			writeUnsatisfiedRange(response, file.Size)
			return
		}
		if len(rangeValues) == 1 {
			rangeHeader = rangeValues[0]
		}
	}
	offset, length, partial, err := parseArtifactRange(rangeHeader, file.Size)
	if err != nil {
		response.Header().Del("Content-Length")
		writeUnsatisfiedRange(response, file.Size)
		return
	}
	opened, err := h.artifacts.OpenPublicFile(request.Context(), workspace, repository, collection, version, filePath, file.ID, offset, length)
	if err != nil {
		// Clear metadata resolved before the second visibility check so a
		// concurrent transition to private does not leak it via the error.
		for _, name := range []string{"Content-Type", "Content-Disposition", "Content-Length", "ETag", "Accept-Ranges"} {
			response.Header().Del(name)
		}
		writeArtifactError(response, err)
		return
	}
	defer opened.Reader.Close()
	response.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	status := http.StatusOK
	if partial {
		status = http.StatusPartialContent
		response.Header().Set("Content-Range", "bytes "+strconv.FormatInt(offset, 10)+"-"+strconv.FormatInt(offset+length-1, 10)+"/"+strconv.FormatInt(file.Size, 10))
	}
	response.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = io.Copy(response, opened.Reader)
	}
}

func (h *authHTTP) publicAssetCORSOrigin(request *http.Request) (string, bool) {
	values := request.Header.Values("Origin")
	if len(values) != 1 {
		return "", false
	}
	value := values[0]
	origin, err := normalizeOrigin(value)
	if err != nil {
		return "", false
	}
	_, allowed := h.publicAssetCORSOrigins[origin]
	return value, allowed
}

func validPublicAssetPreflight(request *http.Request) bool {
	methods := request.Header.Values("Access-Control-Request-Method")
	if len(methods) != 1 || (methods[0] != http.MethodGet && methods[0] != http.MethodHead) {
		return false
	}
	values := request.Header.Values("Access-Control-Request-Headers")
	if len(values) > 1 {
		return false
	}
	if len(values) == 0 {
		return true
	}
	for _, header := range strings.Split(values[0], ",") {
		switch strings.ToLower(strings.TrimSpace(header)) {
		case "range", "if-range", "if-none-match":
		default:
			return false
		}
	}
	return true
}
