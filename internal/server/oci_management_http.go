package server

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/oci"
	"private-registry/internal/repositories"
)

type ociPolicyResponse struct {
	ImmutableTags bool  `json:"immutable_tags"`
	Revision      int64 `json:"revision"`
}

type ociPolicyRequest struct {
	ImmutableTags    *bool  `json:"immutable_tags"`
	ExpectedRevision *int64 `json:"expected_revision"`
}

type ociManifestDeletionResponse struct {
	RemovedTags int `json:"removed_tags"`
}

func (h *authHTTP) registerOCIManagementRoutes(router chi.Router) {
	base := "/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}"
	router.Get(base+"/oci-policy", h.getOCIPolicy)
	router.Put(base+"/oci-policy", h.setOCIPolicy)
	router.Delete(base+"/oci-tags/{tag}", h.deleteOCITag)
	router.Delete(base+"/oci-manifests/{digest}", h.deleteOCIManifest)
}

func writeOCIManagementError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, oci.ErrPolicyRevision):
		writeAPIError(response, http.StatusConflict, "revision_conflict")
	case errors.Is(err, oci.ErrManifestInUse):
		writeAPIError(response, http.StatusConflict, "manifest_in_use")
	case errors.Is(err, oci.ErrTagUnknown), errors.Is(err, oci.ErrManifestUnknown):
		writeAPIError(response, http.StatusNotFound, "not_found")
	case errors.Is(err, oci.ErrNameInvalid), errors.Is(err, oci.ErrDigestInvalid):
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, repositories.ErrFormatMismatch):
		writeAPIError(response, http.StatusNotFound, "not_found")
	case errors.Is(err, oci.ErrUnavailable):
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
	default:
		writeRepositoryError(response, err)
	}
}

func (h *authHTTP) getOCIPolicy(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	policy, err := h.oci.GetPolicy(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"))
	if err != nil {
		writeOCIManagementError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, ociPolicyResponse{ImmutableTags: policy.ImmutableTags, Revision: policy.Revision})
}

func (h *authHTTP) setOCIPolicy(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload ociPolicyRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	if payload.ImmutableTags == nil || payload.ExpectedRevision == nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return
	}
	policy, err := h.oci.SetPolicy(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), *payload.ExpectedRevision, *payload.ImmutableTags)
	if err != nil {
		writeOCIManagementError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, ociPolicyResponse{ImmutableTags: policy.ImmutableTags, Revision: policy.Revision})
}

// deleteOCITag takes the image name from the query because image names
// contain slashes.
func (h *authHTTP) deleteOCITag(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	query := request.URL.Query()
	if len(query) != 1 || len(query["image"]) != 1 {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return
	}
	if err := h.oci.DeleteTag(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), query.Get("image"), chi.URLParam(request, "tag")); err != nil {
		writeOCIManagementError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) deleteOCIManifest(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	if request.URL.RawQuery != "" {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok || !requireRecentMFA(response, session) {
		return
	}
	removed, err := h.oci.DeleteManifest(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), chi.URLParam(request, "digest"))
	if err != nil {
		writeOCIManagementError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, ociManifestDeletionResponse{RemovedTags: removed})
}
