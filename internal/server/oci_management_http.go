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

type ociReviewResponse struct {
	ReviewID    string `json:"review_id"`
	Digest      string `json:"digest"`
	MediaType   string `json:"media_type"`
	Image       string `json:"image"`
	Tag         string `json:"tag,omitempty"`
	SubmittedBy string `json:"submitted_by"`
	SubmittedAt string `json:"submitted_at"`
	Size        int    `json:"size"`
}

func (h *authHTTP) registerOCIReviewRoutes(router chi.Router) {
	base := "/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}"
	router.Get(base+"/oci-review-policy", h.getOCIReviewPolicy)
	router.Put(base+"/oci-review-policy", h.setOCIReviewPolicy)
	router.Get(base+"/oci-reviews", h.listOCIReviews)
	router.Get(base+"/oci-reviews/{reviewID}/manifest", h.getOCIReviewManifest)
	router.Post(base+"/oci-reviews/{reviewID}/approve", h.approveOCIReview)
	router.Post(base+"/oci-reviews/{reviewID}/reject", h.rejectOCIReview)
}

func writeOCIReviewError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, oci.ErrReviewUnknown):
		writeAPIError(response, http.StatusNotFound, "not_found")
	case errors.Is(err, oci.ErrSelfReview):
		writeAPIError(response, http.StatusForbidden, "self_review_forbidden")
	case errors.Is(err, oci.ErrReviewStale):
		writeAPIError(response, http.StatusConflict, "review_stale")
	case errors.Is(err, oci.ErrTagImmutable):
		writeAPIError(response, http.StatusConflict, "tag_immutable")
	case errors.Is(err, oci.ErrQuota):
		writeAPIError(response, http.StatusConflict, "logical_quota_exceeded")
	case errors.Is(err, repositories.ErrReviewPolicyRevision):
		writeAPIError(response, http.StatusConflict, "revision_conflict")
	default:
		writeOCIManagementError(response, err)
	}
}

func (h *authHTTP) getOCIReviewPolicy(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	policy, err := h.repositories.OCIReviewPolicy(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"))
	if err != nil {
		writeOCIReviewError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		Required bool  `json:"required"`
		Revision int64 `json:"revision"`
	}{policy.Required, policy.Revision})
}

func (h *authHTTP) setOCIReviewPolicy(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	var payload struct {
		Required         *bool  `json:"required"`
		ExpectedRevision *int64 `json:"expected_revision"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	if payload.Required == nil || payload.ExpectedRevision == nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	policy, err := h.repositories.SetOCIReviewPolicy(request.Context(), actor, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), *payload.ExpectedRevision, *payload.Required)
	if err != nil {
		writeOCIReviewError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		Required bool  `json:"required"`
		Revision int64 `json:"revision"`
	}{policy.Required, policy.Revision})
}

func (h *authHTTP) listOCIReviews(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	reviews, err := h.oci.ListReviews(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"))
	if err != nil {
		writeOCIReviewError(response, err)
		return
	}
	items := make([]ociReviewResponse, 0, len(reviews))
	for _, review := range reviews {
		items = append(items, ociReviewResponse{ReviewID: review.ID, Digest: review.Digest, MediaType: review.MediaType, Image: review.Image, Tag: review.Tag, SubmittedBy: review.SubmittedBy, SubmittedAt: review.SubmittedAt.Format("2006-01-02T15:04:05.999999999Z07:00"), Size: review.Size})
	}
	writeJSON(response, http.StatusOK, struct {
		Reviews []ociReviewResponse `json:"reviews"`
	}{items})
}

// getOCIReviewManifest returns the submitted document as an attachment so a
// reviewer can inspect it without it being rendered.
func (h *authHTTP) getOCIReviewManifest(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	manifest, err := h.oci.ReviewManifest(request.Context(), session.UserID, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), chi.URLParam(request, "reviewID"))
	if err != nil {
		writeOCIReviewError(response, err)
		return
	}
	setAuthResponseHeaders(response)
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("Content-Disposition", "attachment")
	response.Header().Set("Content-Security-Policy", "sandbox")
	response.Header().Set("X-OCI-Media-Type", manifest.MediaType)
	response.Header().Set("Docker-Content-Digest", manifest.Digest)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(manifest.Content)
}

func (h *authHTTP) approveOCIReview(response http.ResponseWriter, request *http.Request) {
	h.decideOCIReview(response, request, true)
}

func (h *authHTTP) rejectOCIReview(response http.ResponseWriter, request *http.Request) {
	h.decideOCIReview(response, request, false)
}

func (h *authHTTP) decideOCIReview(response http.ResponseWriter, request *http.Request, approve bool) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	if err := h.oci.DecideReview(request.Context(), actor, chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), chi.URLParam(request, "reviewID"), approve); err != nil {
		writeOCIReviewError(response, err)
		return
	}
	writeNoContent(response)
}
