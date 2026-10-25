package server

import (
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/artifacts"
)

const maxDownloadTicketLifetime = 15 * time.Minute

type artifactDownloadLinkRequest struct {
	ExpiresInSeconds int64 `json:"expires_in_seconds"`
}

type artifactDownloadLinkResponse struct {
	DownloadURL string               `json:"download_url"`
	ExpiresAt   string               `json:"expires_at"`
	File        artifactFileResponse `json:"file"`
}

func (h *authHTTP) registerArtifactAssetRoutes(router chi.Router) {
	router.Post("/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/artifacts/{artifactVersionID}/files/{fileID}/download-link", h.issueArtifactDownloadLink)
	router.Get("/api/v1/assets/{token}", h.downloadArtifact)
	router.Head("/api/v1/assets/{token}", h.downloadArtifact)
}

func (h *authHTTP) issueArtifactDownloadLink(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload artifactDownloadLinkRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	if payload.ExpiresInSeconds != 0 &&
		(payload.ExpiresInSeconds < int64(time.Minute/time.Second) || payload.ExpiresInSeconds > int64(maxDownloadTicketLifetime/time.Second)) {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	ttl := time.Duration(payload.ExpiresInSeconds) * time.Second
	ticket, err := h.artifacts.IssueDownloadTicket(
		request.Context(), session.UserID,
		chi.URLParam(request, "workspaceID"),
		chi.URLParam(request, "repositoryID"),
		chi.URLParam(request, "artifactVersionID"),
		chi.URLParam(request, "fileID"),
		ttl,
	)
	if err != nil {
		writeArtifactError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, artifactDownloadLinkResponse{
		DownloadURL: h.assetOrigin + "/api/v1/assets/" + ticket.Token,
		ExpiresAt:   ticket.ExpiresAt.UTC().Format(time.RFC3339Nano),
		File: artifactFileResponse{
			ArtifactFileID: ticket.File.ID,
			Path:           ticket.File.Path,
			ContentType:    ticket.File.ContentType,
			Size:           ticket.File.Size,
			SHA256:         ticket.File.SHA256,
		},
	})
}

func (h *authHTTP) downloadArtifact(response http.ResponseWriter, request *http.Request) {
	if !h.requireAssetRequest(response, request) {
		return
	}
	token := chi.URLParam(request, "token")
	file, _, err := h.artifacts.ResolveDownloadTicket(request.Context(), token)
	if err != nil {
		writeArtifactError(response, err)
		return
	}
	etag := `"` + file.SHA256 + `"`
	setArtifactDownloadHeaders(response, file, etag)
	if matchesETag(request.Header.Values("If-None-Match"), etag) {
		response.WriteHeader(http.StatusNotModified)
		return
	}

	rangeHeader := ""
	ifRangeValues := request.Header.Values("If-Range")
	if len(ifRangeValues) == 0 || (len(ifRangeValues) == 1 && strings.TrimSpace(ifRangeValues[0]) == etag) {
		rangeValues := request.Header.Values("Range")
		if len(rangeValues) > 1 {
			writeUnsatisfiedRange(response, file.Size)
			return
		}
		if len(rangeValues) == 1 {
			rangeHeader = rangeValues[0]
		}
	}
	offset, length, partial, err := parseArtifactRange(rangeHeader, file.Size)
	if err != nil {
		writeUnsatisfiedRange(response, file.Size)
		return
	}
	opened, _, err := h.artifacts.OpenDownloadTicket(request.Context(), token, offset, length)
	if err != nil {
		writeArtifactError(response, err)
		return
	}
	defer opened.Reader.Close()
	response.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	status := http.StatusOK
	if partial {
		status = http.StatusPartialContent
		response.Header().Set("Content-Range", "bytes "+strconv.FormatInt(offset, 10)+"-"+
			strconv.FormatInt(offset+length-1, 10)+"/"+strconv.FormatInt(file.Size, 10))
	}
	response.WriteHeader(status)
	if request.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(response, opened.Reader); err != nil {
		return
	}
}

func (h *authHTTP) requireAssetRequest(response http.ResponseWriter, request *http.Request) bool {
	requestOrigin, err := normalizeOrigin("https://" + request.Host)
	if err != nil || requestOrigin != h.assetOrigin || !requestUsesHTTPS(request, h.trustedProxies) {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return false
	}
	return true
}

func setArtifactDownloadHeaders(response http.ResponseWriter, file artifacts.File, etag string) {
	filename := path.Base(file.Path)
	contentDisposition := mime.FormatMediaType("attachment", map[string]string{"filename": filename})
	if contentDisposition == "" {
		contentDisposition = `attachment; filename="artifact"`
	}
	response.Header().Set("Content-Type", file.ContentType)
	response.Header().Set("Content-Disposition", contentDisposition)
	response.Header().Set("Content-Length", strconv.FormatInt(file.Size, 10))
	response.Header().Set("ETag", etag)
	response.Header().Set("Accept-Ranges", "bytes")
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	response.Header().Set("X-Frame-Options", "DENY")
}

func matchesETag(values []string, etag string) bool {
	for _, value := range values {
		for _, candidate := range strings.Split(value, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "*" || candidate == etag || candidate == "W/"+etag {
				return true
			}
		}
	}
	return false
}

func parseArtifactRange(value string, size int64) (offset int64, length int64, partial bool, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, size, false, nil
	}
	if size < 1 || !strings.HasPrefix(value, "bytes=") || strings.Contains(value, ",") {
		return 0, 0, false, artifacts.ErrInvalidRange
	}
	rangeValue := strings.TrimPrefix(value, "bytes=")
	if strings.Count(rangeValue, "-") != 1 {
		return 0, 0, false, artifacts.ErrInvalidRange
	}
	startValue, endValue, _ := strings.Cut(rangeValue, "-")
	if startValue == "" {
		suffixLength, parseErr := strconv.ParseInt(endValue, 10, 64)
		if parseErr != nil || suffixLength < 1 {
			return 0, 0, false, artifacts.ErrInvalidRange
		}
		if suffixLength > size {
			suffixLength = size
		}
		return size - suffixLength, suffixLength, true, nil
	}
	start, parseErr := strconv.ParseInt(startValue, 10, 64)
	if parseErr != nil || start < 0 || start >= size {
		return 0, 0, false, artifacts.ErrInvalidRange
	}
	end := size - 1
	if endValue != "" {
		end, parseErr = strconv.ParseInt(endValue, 10, 64)
		if parseErr != nil || end < start {
			return 0, 0, false, artifacts.ErrInvalidRange
		}
		if end >= size {
			end = size - 1
		}
	}
	return start, end - start + 1, true, nil
}

func writeUnsatisfiedRange(response http.ResponseWriter, size int64) {
	response.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(size, 10))
	writeArtifactError(response, artifacts.ErrInvalidRange)
}
