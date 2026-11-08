package server

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/npm"
)

func (h *authHTTP) registerNPMTagRoutes(router chi.Router) {
	base := "/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/npm"
	router.Put(base+"/tag-managers/{userID}", h.grantNPMTagManager)
	router.Delete(base+"/tag-managers/{userID}", h.revokeNPMTagManager)
	router.Get(base+"/tags/state", h.getNPMTagState)
	router.Put(base+"/tags", h.setNPMTag)
	router.Delete(base+"/tags", h.removeNPMTag)
}

func writeNPMTagError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, npm.ErrTagUnavailable):
		writeAPIError(response, http.StatusNotFound, "tag_unavailable")
	case errors.Is(err, npm.ErrTagConflict):
		writeAPIError(response, http.StatusConflict, "tag_revision_conflict")
	default:
		writeGoManagementError(response, err)
	}
}

func (h *authHTTP) grantNPMTagManager(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := npmReviewScope(request)
	id, err := h.repositories.GrantNPMTagManager(request.Context(), actor, workspace, repository, chi.URLParam(request, "userID"))
	if err != nil {
		writeNPMTagError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		ID string `json:"grant_id"`
	}{ID: id})
}

func (h *authHTTP) revokeNPMTagManager(response http.ResponseWriter, request *http.Request) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	workspace, repository, _ := npmReviewScope(request)
	if err := h.repositories.RevokeNPMTagManager(request.Context(), actor, workspace, repository, chi.URLParam(request, "userID")); err != nil {
		writeNPMTagError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) getNPMTagState(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	query := request.URL.Query()
	if len(query) != 2 || len(query["name"]) != 1 || len(query["tag"]) != 1 {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	workspace, repository, _ := npmReviewScope(request)
	state, err := h.npmReservations.GetDistTagState(request.Context(), session.UserID, workspace, repository, query.Get("name"), query.Get("tag"))
	if err != nil {
		writeNPMTagError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		Revision int64  `json:"revision"`
		Active   bool   `json:"active"`
		Version  string `json:"version,omitempty"`
	}{state.Revision, state.Active, state.Version})
}

func (h *authHTTP) setNPMTag(response http.ResponseWriter, request *http.Request) {
	h.mutateNPMTag(response, request, false)
}

func (h *authHTTP) removeNPMTag(response http.ResponseWriter, request *http.Request) {
	h.mutateNPMTag(response, request, true)
}

func (h *authHTTP) mutateNPMTag(response http.ResponseWriter, request *http.Request, remove bool) {
	actor, ok := h.goMutation(response, request)
	if !ok {
		return
	}
	request, cancel, ok := goRequestContext(response, request, true)
	if !ok {
		return
	}
	defer cancel()
	var payload struct {
		Name             string `json:"name"`
		Tag              string `json:"tag"`
		Version          string `json:"version"`
		ExpectedRevision *int64 `json:"expected_revision"`
	}
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	if payload.ExpectedRevision == nil || (remove && payload.Version != "") || (!remove && payload.Version == "") {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	workspace, repository, _ := npmReviewScope(request)
	var revision int64
	var err error
	if remove {
		revision, err = h.npmReservations.RemoveDistTag(request.Context(), actor, workspace, repository, payload.Name, payload.Tag, *payload.ExpectedRevision)
	} else {
		revision, err = h.npmReservations.SetDistTag(request.Context(), actor, workspace, repository, payload.Name, payload.Tag, payload.Version, *payload.ExpectedRevision)
	}
	if err != nil {
		writeNPMTagError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		Revision int64 `json:"revision"`
	}{Revision: revision})
}
