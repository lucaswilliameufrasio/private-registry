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
