package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"private-registry/internal/authattempts"
	"private-registry/internal/oci"
)

const (
	ociUploadTimeout   = 30 * time.Minute
	ociMetadataTimeout = time.Minute
	ociChallenge       = `Basic realm="private-registry"`
)

type ociRoute struct {
	workspace  string
	repository string
	image      string
	kind       string // blob, upload, uploads, manifest, tags, referrers
	reference  string
}

// ociName is the full repository name a client uses after /v2/:
// <workspace-id>/<repository-id>/<image path>.
func (r ociRoute) ociName() string {
	return r.workspace + "/" + r.repository + "/" + r.image
}

func (r ociRoute) base() string {
	return "/v2/" + r.ociName()
}

// parseOCIPath splits the path after /v2/. Image names may contain slashes,
// so the operation is recognised from the end of the path.
func parseOCIPath(path string) (ociRoute, bool) {
	segments := strings.Split(path, "/")
	if len(segments) < 5 {
		return ociRoute{}, false
	}
	route := ociRoute{workspace: segments[0], repository: segments[1]}
	for _, id := range []string{route.workspace, route.repository} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return ociRoute{}, false
		}
	}
	rest := segments[2:]
	count := len(rest)
	var image []string
	switch {
	case count >= 3 && rest[count-2] == "tags" && rest[count-1] == "list":
		route.kind, image = "tags", rest[:count-2]
	case count >= 4 && rest[count-3] == "blobs" && rest[count-2] == "uploads":
		route.kind, route.reference, image = "upload", rest[count-1], rest[:count-3]
		if route.reference == "" {
			route.kind = "uploads"
		}
	case count >= 3 && rest[count-2] == "blobs":
		route.kind, route.reference, image = "blob", rest[count-1], rest[:count-2]
	case count >= 3 && rest[count-2] == "manifests":
		route.kind, route.reference, image = "manifest", rest[count-1], rest[:count-2]
	case count >= 3 && rest[count-2] == "referrers":
		route.kind, route.reference, image = "referrers", rest[count-1], rest[:count-2]
	default:
		return ociRoute{}, false
	}
	route.image = strings.Join(image, "/")
	if !oci.ValidImageName(route.image) || (route.kind != "tags" && route.kind != "uploads" && route.reference == "") {
		return ociRoute{}, false
	}
	return route, true
}

func ociError(response http.ResponseWriter, status int, code, message string) {
	setAuthResponseHeaders(response)
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("Vary", "Authorization")
	response.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	if status == http.StatusUnauthorized {
		response.Header().Set("WWW-Authenticate", ociChallenge)
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]any{"errors": []map[string]string{{"code": code, "message": message}}})
}

func writeOCIServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, oci.ErrUnauthorized):
		ociError(response, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
	case errors.Is(err, oci.ErrNameInvalid):
		ociError(response, http.StatusBadRequest, "NAME_INVALID", "invalid repository name")
	case errors.Is(err, oci.ErrDigestInvalid):
		ociError(response, http.StatusBadRequest, "DIGEST_INVALID", "digest is invalid or does not match the content")
	case errors.Is(err, oci.ErrBlobUnknown):
		ociError(response, http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown to registry")
	case errors.Is(err, oci.ErrManifestUnknown):
		ociError(response, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown to registry")
	case errors.Is(err, oci.ErrManifestInvalid):
		ociError(response, http.StatusBadRequest, "MANIFEST_INVALID", "manifest invalid or unsupported")
	case errors.Is(err, oci.ErrManifestBlob):
		ociError(response, http.StatusBadRequest, "MANIFEST_BLOB_UNKNOWN", "manifest references content unknown to this repository")
	case errors.Is(err, oci.ErrUploadUnknown):
		ociError(response, http.StatusNotFound, "BLOB_UPLOAD_UNKNOWN", "blob upload unknown to registry")
	case errors.Is(err, oci.ErrUploadRange):
		ociError(response, http.StatusRequestedRangeNotSatisfiable, "BLOB_UPLOAD_INVALID", "upload chunk is out of order")
	case errors.Is(err, oci.ErrTooLarge):
		ociError(response, http.StatusRequestEntityTooLarge, "SIZE_INVALID", "content exceeds the size limit")
	case errors.Is(err, oci.ErrBusy):
		ociError(response, http.StatusTooManyRequests, "TOOMANYREQUESTS", "upload capacity temporarily full")
	default:
		ociError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "registry temporarily unavailable")
	}
}

// ociBearer accepts the registry token either as a Bearer credential or as
// the password of Basic authentication, which is what `docker login` and
// `oras login` send. The Basic user name is ignored.
func ociBearer(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 512 {
		return "", false
	}
	token := ""
	switch {
	case strings.HasPrefix(values[0], "Bearer "):
		token = strings.TrimPrefix(values[0], "Bearer ")
	case strings.HasPrefix(values[0], "Basic "):
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(values[0], "Basic "))
		if err != nil {
			return "", false
		}
		_, password, found := strings.Cut(string(decoded), ":")
		if !found {
			return "", false
		}
		token = password
	}
	if token == "" || len(token) > 128 || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func (h *authHTTP) ociCanonical(request *http.Request) bool {
	origin, err := normalizeOrigin("https://" + request.Host)
	return err == nil && origin == h.canonicalOrigin && requestUsesHTTPS(request, h.trustedProxies)
}

// ociBase answers the version probe. Tokens are scoped to one repository, so
// this endpoint cannot validate a credential: it only tells an anonymous
// client to authenticate. Real authorization happens on every repository
// request.
func (h *authHTTP) ociBase(response http.ResponseWriter, request *http.Request) {
	if !h.ociCanonical(request) {
		ociError(response, http.StatusForbidden, "DENIED", "registry unavailable")
		return
	}
	if _, ok := ociBearer(request); !ok {
		ociError(response, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}
	setAuthResponseHeaders(response)
	response.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write([]byte("{}"))
}

func (h *authHTTP) ociAuthorize(response http.ResponseWriter, request *http.Request, route ociRoute) (oci.Principal, bool) {
	select {
	case h.personalTokenSlots <- struct{}{}:
		defer func() { <-h.personalTokenSlots }()
	default:
		ociError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "registry temporarily unavailable")
		return oci.Principal{}, false
	}
	source, err := clientAddress(request, h.trustedProxies)
	if err != nil {
		ociError(response, http.StatusBadRequest, "UNSUPPORTED", "invalid request")
		return oci.Principal{}, false
	}
	token, ok := ociBearer(request)
	if !ok {
		// An anonymous probe is how clients discover the challenge; it is
		// answered without consuming the failed-attempt budget.
		ociError(response, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return oci.Principal{}, false
	}
	retryAfter, err := h.service.BeginPersonalToken(request.Context(), source)
	if err != nil {
		if errors.Is(err, authattempts.ErrRateLimited) {
			seconds := int64((retryAfter + time.Second - 1) / time.Second)
			if seconds < 1 {
				seconds = 1
			}
			response.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
			ociError(response, http.StatusTooManyRequests, "TOOMANYREQUESTS", "rate limited")
		} else {
			ociError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "registry temporarily unavailable")
		}
		return oci.Principal{}, false
	}
	principal, err := h.oci.Authorize(request.Context(), token, route.workspace, route.repository)
	if err != nil {
		writeOCIServiceError(response, err)
		return oci.Principal{}, false
	}
	if h.service.CompletePersonalToken(request.Context(), source) != nil {
		ociError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "registry temporarily unavailable")
		return oci.Principal{}, false
	}
	return principal, true
}

func (h *authHTTP) ociDispatch(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/v2/" {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			ociError(response, http.StatusMethodNotAllowed, "UNSUPPORTED", "operation is not supported")
			return
		}
		h.ociBase(response, request)
		return
	}
	if !h.ociCanonical(request) {
		ociError(response, http.StatusForbidden, "DENIED", "registry unavailable")
		return
	}
	// The escaped path is used so an encoded slash cannot smuggle a segment.
	escaped := request.URL.EscapedPath()
	if strings.Contains(escaped, "%") {
		ociError(response, http.StatusNotFound, "NAME_UNKNOWN", "repository name not known to registry")
		return
	}
	route, ok := parseOCIPath(strings.TrimPrefix(escaped, "/v2/"))
	if !ok {
		ociError(response, http.StatusNotFound, "NAME_UNKNOWN", "repository name not known to registry")
		return
	}
	principal, ok := h.ociAuthorize(response, request, route)
	if !ok {
		return
	}
	write := request.Method != http.MethodGet && request.Method != http.MethodHead
	// A publisher without a reader grant may still probe blob existence and
	// upload progress, which pushing requires, but cannot download content.
	readAllowed := principal.CanRead || (principal.CanWrite && ((route.kind == "blob" && request.Method == http.MethodHead) || route.kind == "upload"))
	if (write && !principal.CanWrite) || (!write && !readAllowed) {
		ociError(response, http.StatusForbidden, "DENIED", "requested access to the resource is denied")
		return
	}
	response.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	switch {
	case route.kind == "uploads" && request.Method == http.MethodPost:
		h.ociStartUpload(response, request, route, principal)
	case route.kind == "upload" && request.Method == http.MethodPatch:
		h.ociPatchUpload(response, request, route, principal)
	case route.kind == "upload" && request.Method == http.MethodPut:
		h.ociFinishUpload(response, request, route, principal, route.reference)
	case route.kind == "upload" && request.Method == http.MethodGet:
		size, err := h.oci.UploadSize(principal, route.workspace, route.repository, route.reference)
		if err != nil {
			writeOCIServiceError(response, err)
			return
		}
		h.ociUploadProgress(response, route, route.reference, size, http.StatusNoContent)
	case route.kind == "upload" && request.Method == http.MethodDelete:
		if err := h.oci.CancelUpload(principal, route.workspace, route.repository, route.reference); err != nil {
			writeOCIServiceError(response, err)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	case route.kind == "blob" && (request.Method == http.MethodGet || request.Method == http.MethodHead):
		h.ociBlob(response, request, route)
	case route.kind == "manifest" && request.Method == http.MethodPut:
		h.ociPutManifest(response, request, route, principal)
	case route.kind == "manifest" && (request.Method == http.MethodGet || request.Method == http.MethodHead):
		h.ociManifest(response, request, route)
	case route.kind == "tags" && request.Method == http.MethodGet:
		h.ociTags(response, request, route)
	case route.kind == "referrers" && request.Method == http.MethodGet:
		// The referrers API is not implemented; clients fall back to the
		// referrers tag schema when they receive 404.
		ociError(response, http.StatusNotFound, "NAME_UNKNOWN", "referrers API is not supported")
	default:
		// Deleting blobs, manifests and tags is intentionally unsupported.
		ociError(response, http.StatusMethodNotAllowed, "UNSUPPORTED", "operation is not supported")
	}
}

func (h *authHTTP) ociUploadProgress(response http.ResponseWriter, route ociRoute, id string, size int64, status int) {
	response.Header().Set("Location", route.base()+"/blobs/uploads/"+id)
	response.Header().Set("Docker-Upload-UUID", id)
	end := size - 1
	if end < 0 {
		end = 0
	}
	response.Header().Set("Range", "0-"+strconv.FormatInt(end, 10))
	response.Header().Set("Content-Length", "0")
	response.WriteHeader(status)
}

func (h *authHTTP) ociBodyDeadline(response http.ResponseWriter, request *http.Request) (*http.Request, func(), bool) {
	deadline := time.Now().Add(ociUploadTimeout)
	controller := http.NewResponseController(response)
	if err := controller.SetReadDeadline(deadline); err != nil {
		ociError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "registry temporarily unavailable")
		return request, func() {}, false
	}
	ctx, cancel := contextWithDeadline(request, deadline)
	return request.WithContext(ctx), func() {
		cancel()
		_ = controller.SetReadDeadline(time.Time{})
	}, true
}

func (h *authHTTP) ociStartUpload(response http.ResponseWriter, request *http.Request, route ociRoute, principal oci.Principal) {
	query := request.URL.Query()
	// Cross-repository mount is not offered: the client receives a normal
	// upload session, as the distribution specification allows.
	id, err := h.oci.StartUpload(principal, route.workspace, route.repository)
	if err != nil {
		writeOCIServiceError(response, err)
		return
	}
	if digest := query.Get("digest"); digest != "" && query.Get("mount") == "" {
		h.ociFinishUpload(response, request, route, principal, id)
		return
	}
	h.ociUploadProgress(response, route, id, 0, http.StatusAccepted)
}

func (h *authHTTP) ociPatchUpload(response http.ResponseWriter, request *http.Request, route ociRoute, principal oci.Principal) {
	offset := int64(-1)
	if raw := request.Header.Get("Content-Range"); raw != "" {
		start, _, found := strings.Cut(raw, "-")
		parsed, err := strconv.ParseInt(start, 10, 64)
		if !found || err != nil || parsed < 0 {
			ociError(response, http.StatusBadRequest, "BLOB_UPLOAD_INVALID", "invalid Content-Range")
			return
		}
		offset = parsed
	}
	request, done, ok := h.ociBodyDeadline(response, request)
	if !ok {
		return
	}
	defer done()
	size, err := h.oci.AppendUpload(request.Context(), principal, route.workspace, route.repository, route.reference, offset, request.Body)
	if err != nil {
		writeOCIServiceError(response, err)
		return
	}
	h.ociUploadProgress(response, route, route.reference, size, http.StatusAccepted)
}

func (h *authHTTP) ociFinishUpload(response http.ResponseWriter, request *http.Request, route ociRoute, principal oci.Principal, id string) {
	digest := request.URL.Query().Get("digest")
	if !oci.ValidDigest(digest) {
		_ = h.oci.CancelUpload(principal, route.workspace, route.repository, id)
		ociError(response, http.StatusBadRequest, "DIGEST_INVALID", "a sha256 digest is required")
		return
	}
	request, done, ok := h.ociBodyDeadline(response, request)
	if !ok {
		return
	}
	defer done()
	if _, err := h.oci.FinishUpload(request.Context(), principal, route.workspace, route.repository, id, digest, request.Body); err != nil {
		writeOCIServiceError(response, err)
		return
	}
	response.Header().Set("Location", route.base()+"/blobs/"+digest)
	response.Header().Set("Docker-Content-Digest", digest)
	response.Header().Set("Content-Length", "0")
	response.WriteHeader(http.StatusCreated)
}

func (h *authHTTP) ociBlob(response http.ResponseWriter, request *http.Request, route ociRoute) {
	ctx, cancel := contextWithDeadline(request, time.Now().Add(ociUploadTimeout))
	defer cancel()
	setOCIContentHeaders := func(size int64) {
		response.Header().Set("Cache-Control", "private, no-store")
		response.Header().Set("Vary", "Authorization")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Content-Type", "application/octet-stream")
		response.Header().Set("Docker-Content-Digest", route.reference)
		response.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	if request.Method == http.MethodHead {
		size, err := h.oci.StatBlob(ctx, route.repository, route.reference)
		if err != nil {
			writeOCIServiceError(response, err)
			return
		}
		setOCIContentHeaders(size)
		response.WriteHeader(http.StatusOK)
		return
	}
	reader, size, err := h.oci.OpenBlob(ctx, route.workspace, route.repository, route.reference)
	if err != nil {
		writeOCIServiceError(response, err)
		return
	}
	defer reader.Close()
	setOCIContentHeaders(size)
	response.WriteHeader(http.StatusOK)
	_, _ = io.Copy(response, reader)
}

func (h *authHTTP) ociPutManifest(response http.ResponseWriter, request *http.Request, route ociRoute, principal oci.Principal) {
	contentType := ""
	if raw := request.Header.Get("Content-Type"); raw != "" {
		parsed, _, err := mime.ParseMediaType(raw)
		if err != nil {
			ociError(response, http.StatusBadRequest, "MANIFEST_INVALID", "invalid Content-Type")
			return
		}
		contentType = parsed
	}
	deadline := time.Now().Add(ociMetadataTimeout)
	controller := http.NewResponseController(response)
	if err := controller.SetReadDeadline(deadline); err != nil {
		ociError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "registry temporarily unavailable")
		return
	}
	defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
	ctx, cancel := contextWithDeadline(request, deadline)
	defer cancel()
	body, err := io.ReadAll(io.LimitReader(request.Body, oci.MaxManifestBytes+1))
	if err != nil {
		ociError(response, http.StatusBadRequest, "MANIFEST_INVALID", "manifest could not be read")
		return
	}
	if len(body) > oci.MaxManifestBytes {
		ociError(response, http.StatusRequestEntityTooLarge, "SIZE_INVALID", "manifest exceeds the size limit")
		return
	}
	digest, err := h.oci.PutManifest(ctx, principal, route.workspace, route.repository, route.image, route.reference, contentType, body)
	if err != nil {
		writeOCIServiceError(response, err)
		return
	}
	response.Header().Set("Location", route.base()+"/manifests/"+digest)
	response.Header().Set("Docker-Content-Digest", digest)
	response.Header().Set("Content-Length", "0")
	response.WriteHeader(http.StatusCreated)
}

func (h *authHTTP) ociManifest(response http.ResponseWriter, request *http.Request, route ociRoute) {
	ctx, cancel := contextWithDeadline(request, time.Now().Add(ociMetadataTimeout))
	defer cancel()
	manifest, err := h.oci.GetManifest(ctx, route.repository, route.image, route.reference)
	if err != nil {
		writeOCIServiceError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("Vary", "Authorization")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Content-Type", manifest.MediaType)
	response.Header().Set("Docker-Content-Digest", manifest.Digest)
	response.Header().Set("Content-Length", strconv.Itoa(len(manifest.Content)))
	response.WriteHeader(http.StatusOK)
	if request.Method == http.MethodGet {
		_, _ = response.Write(manifest.Content)
	}
}

func (h *authHTTP) ociTags(response http.ResponseWriter, request *http.Request, route ociRoute) {
	query := request.URL.Query()
	limit := 100
	if raw := query.Get("n"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			ociError(response, http.StatusBadRequest, "UNSUPPORTED", "invalid page size")
			return
		}
		if parsed < limit {
			limit = parsed
		}
	}
	ctx, cancel := contextWithDeadline(request, time.Now().Add(ociMetadataTimeout))
	defer cancel()
	tags, err := h.oci.ListTags(ctx, route.repository, route.image, query.Get("last"), limit+1)
	if err != nil {
		writeOCIServiceError(response, err)
		return
	}
	if len(tags) > limit {
		tags = tags[:limit]
		next := url.Values{"n": {strconv.Itoa(limit)}, "last": {tags[len(tags)-1]}}
		response.Header().Set("Link", "<"+route.base()+"/tags/list?"+next.Encode()+`>; rel="next"`)
	}
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("Vary", "Authorization")
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(response).Encode(map[string]any{"name": route.ociName(), "tags": tags})
}

func contextWithDeadline(request *http.Request, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(request.Context(), deadline)
}
