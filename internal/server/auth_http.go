package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/artifacts"
	"private-registry/internal/auth"
	"private-registry/internal/gomod"
	"private-registry/internal/repositories"
	"private-registry/internal/sessions"
	"private-registry/internal/workspaces"
)

const (
	maxAuthRequestBytes        = 8 << 10
	maxForwardedForHeaderBytes = 2048
	workspaceCreationMFAMaxAge = 5 * time.Minute
	sessionCookieName          = "__Host-registry-session"
	csrfCookieName             = "__Host-registry-csrf"
	csrfHeaderName             = "X-CSRF-Token"
)

type AuthHTTPConfig struct {
	CanonicalOrigin        string
	AssetOrigin            string
	TrustedProxies         []netip.Prefix
	PublicAssetCORSOrigins []string
	GoModules              *gomod.Service
}

type authHTTP struct {
	service                *auth.Service
	workspaces             *workspaces.Service
	repositories           *repositories.Service
	artifacts              *artifacts.Service
	goModules              *gomod.Service
	goMetadataSlots        chan struct{}
	maxUploadBytes         int64
	canonicalOrigin        string
	assetOrigin            string
	trustedProxies         []netip.Prefix
	publicAssetCORSOrigins map[string]struct{}
	personalTokenSlots     chan struct{}
}

type loginRequest struct {
	LoginName string `json:"login_name"`
	Password  string `json:"password"`
}

type codeRequest struct {
	Code string `json:"code"`
}

type loginResponse struct {
	Stage string `json:"stage"`
}

type enrollmentResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
	ExpiresAt  string `json:"expires_at"`
}

type enrollmentCompletionResponse struct {
	Stage         string   `json:"stage"`
	RecoveryCodes []string `json:"recovery_codes"`
}

type workspaceCreateRequest struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

type workspaceMembershipRequest struct {
	Role string `json:"role"`
}

type repositoryCreateRequest struct {
	Slug        string          `json:"slug"`
	DisplayName string          `json:"display_name"`
	Format      json.RawMessage `json:"format"`
}

type repositoryUpdateRequest struct {
	DisplayName string `json:"display_name"`
}

type repositoryVisibilityRequest struct {
	Visibility    string `json:"visibility"`
	ConfirmPublic bool   `json:"confirm_public"`
}

type repositoryVisibilityPolicyRequest struct {
	Policy string `json:"policy"`
}

type workspaceItemResponse struct {
	WorkspaceID string `json:"workspace_id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

type workspaceListResponse struct {
	Workspaces []workspaceItemResponse `json:"workspaces"`
	HasMore    bool                    `json:"has_more"`
	NextCursor string                  `json:"next_cursor,omitempty"`
}

type repositoryItemResponse struct {
	RepositoryID string `json:"repository_id"`
	WorkspaceID  string `json:"workspace_id"`
	Slug         string `json:"slug"`
	DisplayName  string `json:"display_name"`
	Visibility   string `json:"visibility"`
	Format       string `json:"format"`
}

type repositoryListResponse struct {
	Repositories []repositoryItemResponse `json:"repositories"`
	HasMore      bool                     `json:"has_more"`
	NextCursor   string                   `json:"next_cursor,omitempty"`
}

type repositoryVisibilityPolicyResponse struct {
	Policy string `json:"policy"`
}

type repositoryGrantItemResponse struct {
	GrantID      string `json:"grant_id"`
	RepositoryID string `json:"repository_id"`
	WorkspaceID  string `json:"workspace_id"`
	UserID       string `json:"user_id"`
	Role         string `json:"role"`
	GrantedBy    string `json:"granted_by"`
	GrantedAt    string `json:"granted_at"`
}

type repositoryGrantListResponse struct {
	Grants     []repositoryGrantItemResponse `json:"grants"`
	HasMore    bool                          `json:"has_more"`
	NextCursor string                        `json:"next_cursor,omitempty"`
}

type artifactUploadRequest struct {
	Collection  string `json:"collection"`
	Version     string `json:"version"`
	Path        string `json:"path"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

type artifactUploadResponse struct {
	UploadSessionID   string `json:"upload_session_id"`
	ArtifactVersionID string `json:"artifact_version_id"`
	Path              string `json:"path"`
	Status            string `json:"status"`
	ExpiresAt         string `json:"expires_at"`
}

type artifactFileResponse struct {
	ArtifactFileID string `json:"artifact_file_id"`
	Path           string `json:"path"`
	ContentType    string `json:"content_type"`
	Size           int64  `json:"size"`
	SHA256         string `json:"sha256"`
}

type artifactVersionResponse struct {
	ArtifactVersionID string                 `json:"artifact_version_id"`
	WorkspaceID       string                 `json:"workspace_id"`
	RepositoryID      string                 `json:"repository_id"`
	Collection        string                 `json:"collection"`
	Version           string                 `json:"version"`
	Status            string                 `json:"status"`
	PublishedAt       string                 `json:"published_at,omitempty"`
	Files             []artifactFileResponse `json:"files"`
}

type apiErrorResponse struct {
	Error string `json:"error"`
}

// NewHandler composes health probes, authentication, administration, and the
// private generic-artifact publication flow. Asset delivery remains on a
// separate origin and is not served by this administrative router.
func NewHandler(
	health *Health,
	service *auth.Service,
	workspaceService *workspaces.Service,
	repositoryService *repositories.Service,
	artifactService *artifacts.Service,
	cfg AuthHTTPConfig,
) (http.Handler, error) {
	if health == nil || service == nil || workspaceService == nil || repositoryService == nil || artifactService == nil {
		return nil, errors.New("health, authentication, workspace, repository, and artifact services are required")
	}
	canonicalOrigin, err := normalizeOrigin(cfg.CanonicalOrigin)
	if err != nil {
		return nil, errors.New("a valid HTTPS canonical origin is required")
	}
	assetOrigin, err := normalizeOrigin(cfg.AssetOrigin)
	if err != nil || assetOrigin == canonicalOrigin {
		return nil, errors.New("a distinct HTTPS asset origin is required")
	}
	if len(cfg.PublicAssetCORSOrigins) > 32 {
		return nil, errors.New("public asset CORS origins exceed the limit")
	}
	corsOrigins := make(map[string]struct{}, len(cfg.PublicAssetCORSOrigins))
	for _, raw := range cfg.PublicAssetCORSOrigins {
		origin, err := normalizeOrigin(raw)
		if err != nil {
			return nil, errors.New("public asset CORS origins must be HTTPS origins")
		}
		corsOrigins[origin] = struct{}{}
	}
	for _, proxy := range cfg.TrustedProxies {
		if !proxy.IsValid() {
			return nil, errors.New("trusted proxy configuration is invalid")
		}
	}

	router := chi.NewRouter()
	health.registerRoutes(router)
	authentication := &authHTTP{
		service:                service,
		workspaces:             workspaceService,
		repositories:           repositoryService,
		artifacts:              artifactService,
		goModules:              cfg.GoModules,
		goMetadataSlots:        make(chan struct{}, 4),
		maxUploadBytes:         artifactService.MaxUploadBytes(),
		canonicalOrigin:        canonicalOrigin,
		assetOrigin:            assetOrigin,
		trustedProxies:         append([]netip.Prefix(nil), cfg.TrustedProxies...),
		publicAssetCORSOrigins: corsOrigins,
		personalTokenSlots:     make(chan struct{}, 16),
	}
	authentication.registerRoutes(router)
	return router, nil
}

func (h *authHTTP) registerRoutes(router chi.Router) {
	router.Post("/api/v1/auth/login", h.login)
	router.Post("/api/v1/auth/mfa/enrollment", h.beginMFAEnrollment)
	router.Post("/api/v1/auth/mfa/enrollment/start", h.beginVoluntaryMFAEnrollment)
	router.Post("/api/v1/auth/mfa/enrollment/complete", h.completeMFAEnrollment)
	router.Post("/api/v1/auth/mfa/challenge", h.completeMFAChallenge)
	router.Post("/api/v1/auth/logout", h.logout)
	router.Get("/api/v1/workspaces", h.listWorkspaces)
	router.Post("/api/v1/workspaces", h.createWorkspace)
	router.Put("/api/v1/workspaces/{workspaceID}/members/{userID}", h.setWorkspaceMembership)
	router.Delete("/api/v1/workspaces/{workspaceID}/members/{userID}", h.removeWorkspaceMembership)
	router.Get("/api/v1/workspaces/{workspaceID}/repositories", h.listRepositories)
	router.Post("/api/v1/workspaces/{workspaceID}/repositories", h.createRepository)
	router.Patch("/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}", h.updateRepository)
	router.Patch("/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/visibility", h.setRepositoryVisibility)
	router.Get("/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/grants", h.listRepositoryGrants)
	router.Put("/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/grants/{userID}/{role}", h.grantRepositoryRole)
	router.Delete("/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/grants/{userID}/{role}", h.revokeRepositoryRole)
	router.Post("/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/artifacts/uploads", h.startArtifactUpload)
	router.Put("/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/artifacts/uploads/{uploadSessionID}", h.receiveArtifactUpload)
	router.Get("/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/artifacts/{artifactVersionID}", h.getArtifactVersion)
	router.Post("/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/artifacts/{artifactVersionID}/publish", h.publishArtifactVersion)
	h.registerArtifactAssetRoutes(router)
	router.Get("/api/v1/admin/repository-visibility-policy", h.getRepositoryVisibilityPolicy)
	router.Put("/api/v1/admin/repository-visibility-policy", h.setRepositoryVisibilityPolicy)
	router.Get("/api/v1/admin/workspaces/{workspaceID}/generic-logical-quota", h.getLogicalQuota)
	router.Get("/api/v1/admin/workspaces/{workspaceID}/generic-logical-usage", h.getGenericLogicalUsage)
	router.Put("/api/v1/admin/workspaces/{workspaceID}/generic-logical-quota", h.setLogicalQuota)
	router.Get("/api/v1/admin/workspaces/{workspaceID}/repositories/{repositoryID}/generic-logical-quota", h.getLogicalQuota)
	router.Put("/api/v1/admin/workspaces/{workspaceID}/repositories/{repositoryID}/generic-logical-quota", h.setLogicalQuota)
	router.Get("/api/v1/admin/jobs/dead", h.listDeadJobs)
	router.Post("/api/v1/admin/jobs/{jobID}/retry", h.retryDeadJob)
	router.Get("/api/v1/admin/jobs/recovery", h.listRecoveryJobs)
	router.Post("/api/v1/admin/jobs/{jobID}/release-recovery", h.releaseRecoveryJob)
	router.Post("/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/personal-read-tokens", h.issuePersonalReadToken)
	router.Get("/api/v1/personal-read-tokens", h.listPersonalReadTokens)
	router.Delete("/api/v1/personal-read-tokens/{tokenID}", h.revokePersonalReadToken)
	router.Post("/api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/cargo-write-tokens", h.issueCargoWriteToken)
	router.Get("/api/v1/cargo-write-tokens", h.listCargoWriteTokens)
	router.Delete("/api/v1/cargo-write-tokens/{tokenID}", h.revokeCargoWriteToken)
	router.Get("/api/v1/token/workspaces/{workspaceID}/repositories/{repositoryID}/artifacts/{artifactVersionID}", h.personalTokenManifest)
	router.Get("/api/v1/token/workspaces/{workspaceID}/repositories/{repositoryID}/files/{fileID}", h.personalTokenFile)
	router.Head("/api/v1/token/workspaces/{workspaceID}/repositories/{repositoryID}/files/{fileID}", h.personalTokenFile)
	if h.goModules != nil {
		router.Get("/go/{workspaceID}/{repositoryID}/*", h.goModuleProxy)
		router.Head("/go/{workspaceID}/{repositoryID}/*", h.goModuleProxy)
		h.registerGoManagementRoutes(router)
	}
}

func (h *authHTTP) login(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload loginRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	sourceAddress, err := clientAddress(request, h.trustedProxies)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	passwordValue := []byte(payload.Password)
	defer clear(passwordValue)

	result, err := h.service.Login(request.Context(), payload.LoginName, passwordValue, sourceAddress)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	if result.Credentials.BearerToken == "" || result.Credentials.CSRFToken == "" {
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	stage := string(result.Stage)
	switch result.Stage {
	case auth.StageAuthenticated, auth.StageMFAChallenge, auth.StageMFAEnrollment:
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	setSessionCookies(response, result.Credentials)
	writeJSON(response, http.StatusOK, loginResponse{Stage: stage})
}

func (h *authHTTP) beginMFAEnrollment(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	bearerToken, _, ok := h.validateBrowserSession(response, request)
	if !ok {
		return
	}
	enrollment, err := h.service.BeginMFAEnrollment(request.Context(), bearerToken)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, enrollmentResponse{
		Secret:     enrollment.Secret,
		OTPAuthURL: enrollment.OTPAuthURL,
		ExpiresAt:  enrollment.ExpiresAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	})
}

func (h *authHTTP) beginVoluntaryMFAEnrollment(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	bearerToken, _, _, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	started, err := h.service.BeginVoluntaryMFAEnrollment(request.Context(), bearerToken)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	setSessionCookies(response, started.Credentials)
	writeJSON(response, http.StatusOK, enrollmentResponse{
		Secret:     started.Enrollment.Secret,
		OTPAuthURL: started.Enrollment.OTPAuthURL,
		ExpiresAt:  started.Enrollment.ExpiresAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	})
}

func (h *authHTTP) completeMFAEnrollment(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload codeRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	bearerToken, _, ok := h.validateBrowserSession(response, request)
	if !ok {
		return
	}
	sourceAddress, err := clientAddress(request, h.trustedProxies)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	completion, err := h.service.CompleteMFAEnrollment(
		request.Context(), bearerToken, payload.Code, sourceAddress)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	if completion.Credentials.BearerToken == "" || completion.Credentials.CSRFToken == "" ||
		len(completion.RecoveryCodes) != 10 {
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	setSessionCookies(response, completion.Credentials)
	writeJSON(response, http.StatusOK, enrollmentCompletionResponse{
		Stage:         string(auth.StageAuthenticated),
		RecoveryCodes: completion.RecoveryCodes,
	})
}

func (h *authHTTP) completeMFAChallenge(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload codeRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	bearerToken, _, ok := h.validateBrowserSession(response, request)
	if !ok {
		return
	}
	sourceAddress, err := clientAddress(request, h.trustedProxies)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	credentials, err := h.service.CompleteMFA(request.Context(), bearerToken, payload.Code, sourceAddress)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	if credentials.BearerToken == "" || credentials.CSRFToken == "" {
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	setSessionCookies(response, credentials)
	writeJSON(response, http.StatusOK, loginResponse{Stage: string(auth.StageAuthenticated)})
}

func (h *authHTTP) listWorkspaces(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	afterWorkspaceID, pageSize, valid := parseWorkspaceListQuery(request)
	if !valid {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	memberships, hasMore, err := h.workspaces.ListForUser(
		request.Context(), session.UserID, afterWorkspaceID, pageSize)
	if err != nil {
		writeWorkspaceError(response, err)
		return
	}
	items := make([]workspaceItemResponse, 0, len(memberships))
	for _, membership := range memberships {
		items = append(items, workspaceItemResponse{
			WorkspaceID: membership.Workspace.ID,
			Slug:        membership.Workspace.Slug,
			DisplayName: membership.Workspace.DisplayName,
			Role:        membership.Role,
		})
	}
	result := workspaceListResponse{Workspaces: items, HasMore: hasMore}
	if hasMore && len(memberships) > 0 {
		result.NextCursor = memberships[len(memberships)-1].Workspace.ID
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *authHTTP) createWorkspace(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload workspaceCreateRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	workspace, err := h.workspaces.CreateWorkspace(request.Context(), session.UserID, payload.Slug, payload.DisplayName)
	if err != nil {
		writeWorkspaceError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, workspaceItemResponse{
		WorkspaceID: workspace.ID,
		Slug:        workspace.Slug,
		DisplayName: workspace.DisplayName,
		Role:        "owner",
	})
}

func (h *authHTTP) setWorkspaceMembership(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload workspaceMembershipRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	if err := h.workspaces.SetMembershipRole(request.Context(), session.UserID,
		chi.URLParam(request, "workspaceID"), chi.URLParam(request, "userID"), payload.Role); err != nil {
		writeWorkspaceError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) removeWorkspaceMembership(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	if err := h.workspaces.RemoveMembership(request.Context(), session.UserID,
		chi.URLParam(request, "workspaceID"), chi.URLParam(request, "userID")); err != nil {
		writeWorkspaceError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) startArtifactUpload(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload artifactUploadRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	uploadSession, err := h.artifacts.StartUpload(request.Context(), session.UserID,
		chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), artifacts.StartUploadRequest{
			Collection:  payload.Collection,
			Version:     payload.Version,
			Path:        payload.Path,
			ContentType: payload.ContentType,
			Size:        payload.Size,
			SHA256:      payload.SHA256,
		})
	if err != nil {
		writeArtifactError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, artifactUploadResponse{
		UploadSessionID:   uploadSession.ID,
		ArtifactVersionID: uploadSession.ArtifactVersionID,
		Path:              uploadSession.Path,
		Status:            uploadSession.Status,
		ExpiresAt:         uploadSession.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

func (h *authHTTP) receiveArtifactUpload(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/octet-stream" {
		writeAPIError(response, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	if request.ContentLength > h.maxUploadBytes {
		writeAPIError(response, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	limitedBody := http.MaxBytesReader(response, request.Body, h.maxUploadBytes)
	uploadSession, err := h.artifacts.ReceiveUpload(request.Context(), session.UserID,
		chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"),
		chi.URLParam(request, "uploadSessionID"), limitedBody)
	if err != nil {
		writeArtifactError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, artifactUploadResponse{
		UploadSessionID:   uploadSession.ID,
		ArtifactVersionID: uploadSession.ArtifactVersionID,
		Path:              uploadSession.Path,
		Status:            uploadSession.Status,
		ExpiresAt:         uploadSession.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

func (h *authHTTP) publishArtifactVersion(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	artifactVersion, err := h.artifacts.Publish(request.Context(), session.UserID,
		chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"),
		chi.URLParam(request, "artifactVersionID"))
	if err != nil {
		writeArtifactError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, toArtifactVersionResponse(artifactVersion))
}

func (h *authHTTP) getArtifactVersion(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	artifactVersion, err := h.artifacts.GetPublishedVersion(request.Context(), session.UserID,
		chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"),
		chi.URLParam(request, "artifactVersionID"))
	if err != nil {
		writeArtifactError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, toArtifactVersionResponse(artifactVersion))
}

func (h *authHTTP) listRepositories(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	workspaceID := chi.URLParam(request, "workspaceID")
	afterRepositoryID, pageSize, valid := parseRepositoryListQuery(request)
	if !valid {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	items, hasMore, err := h.repositories.ListForWorkspace(
		request.Context(), session.UserID, workspaceID, afterRepositoryID, pageSize)
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	result := repositoryListResponse{
		Repositories: make([]repositoryItemResponse, 0, len(items)),
		HasMore:      hasMore,
	}
	for _, repository := range items {
		result.Repositories = append(result.Repositories, repositoryItemResponse{
			RepositoryID: repository.ID,
			WorkspaceID:  repository.WorkspaceID,
			Slug:         repository.Slug,
			DisplayName:  repository.DisplayName,
			Visibility:   string(repository.Visibility),
			Format:       string(repository.Format),
		})
	}
	if hasMore && len(items) > 0 {
		result.NextCursor = items[len(items)-1].ID
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *authHTTP) createRepository(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload repositoryCreateRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	format := repositories.FormatGeneric
	if len(payload.Format) > 0 {
		var value string
		if bytes.Equal(bytes.TrimSpace(payload.Format), []byte("null")) || json.Unmarshal(payload.Format, &value) != nil {
			writeRepositoryError(response, repositories.ErrInvalidFormat)
			return
		}
		format = repositories.Format(value)
	}
	repository, err := h.repositories.CreateWithFormat(request.Context(), session.UserID,
		chi.URLParam(request, "workspaceID"), payload.Slug, payload.DisplayName, format)
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, repositoryItemResponse{
		RepositoryID: repository.ID,
		WorkspaceID:  repository.WorkspaceID,
		Slug:         repository.Slug,
		DisplayName:  repository.DisplayName,
		Visibility:   string(repository.Visibility),
		Format:       string(repository.Format),
	})
}

func (h *authHTTP) updateRepository(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload repositoryUpdateRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	if err := h.repositories.UpdateDisplayName(request.Context(), session.UserID,
		chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"), payload.DisplayName); err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) setRepositoryVisibility(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload repositoryVisibilityRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	if err := h.repositories.SetVisibility(request.Context(), session.UserID,
		chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"),
		repositories.Visibility(payload.Visibility), payload.ConfirmPublic); err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) listRepositoryGrants(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	afterGrantID, pageSize, valid := parseRepositoryGrantListQuery(request)
	if !valid {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	grants, hasMore, err := h.repositories.ListRepositoryGrants(
		request.Context(), session.UserID, chi.URLParam(request, "workspaceID"),
		chi.URLParam(request, "repositoryID"), afterGrantID, pageSize)
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	result := repositoryGrantListResponse{
		Grants:  make([]repositoryGrantItemResponse, 0, len(grants)),
		HasMore: hasMore,
	}
	for _, grant := range grants {
		result.Grants = append(result.Grants, repositoryGrantItemResponse{
			GrantID:      grant.ID,
			RepositoryID: grant.RepositoryID,
			WorkspaceID:  grant.WorkspaceID,
			UserID:       grant.UserID,
			Role:         string(grant.Role),
			GrantedBy:    grant.GrantedBy,
			GrantedAt:    grant.GrantedAt.Format(time.RFC3339Nano),
		})
	}
	if hasMore && len(grants) > 0 {
		result.NextCursor = grants[len(grants)-1].ID
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *authHTTP) grantRepositoryRole(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	grant, err := h.repositories.GrantRepositoryRole(request.Context(), session.UserID,
		chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"),
		chi.URLParam(request, "userID"), repositories.GrantRole(chi.URLParam(request, "role")))
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, repositoryGrantItemResponse{
		GrantID:      grant.ID,
		RepositoryID: grant.RepositoryID,
		WorkspaceID:  grant.WorkspaceID,
		UserID:       grant.UserID,
		Role:         string(grant.Role),
		GrantedBy:    grant.GrantedBy,
		GrantedAt:    grant.GrantedAt.Format(time.RFC3339Nano),
	})
}

func (h *authHTTP) revokeRepositoryRole(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	if err := h.repositories.RevokeRepositoryRole(request.Context(), session.UserID,
		chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID"),
		chi.URLParam(request, "userID"), repositories.GrantRole(chi.URLParam(request, "role"))); err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeNoContent(response)
}

func (h *authHTTP) getRepositoryVisibilityPolicy(response http.ResponseWriter, request *http.Request) {
	session, ok := h.validateAuthenticatedSession(response, request)
	if !ok {
		return
	}
	policy, err := h.repositories.VisibilityPolicy(request.Context(), session.UserID)
	if err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, repositoryVisibilityPolicyResponse{Policy: string(policy)})
}

func (h *authHTTP) setRepositoryVisibilityPolicy(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	var payload repositoryVisibilityPolicyRequest
	if status := decodeJSONBody(response, request, &payload); status != 0 {
		writeAPIError(response, status, requestErrorCode(status))
		return
	}
	_, _, session, ok := h.validateBrowserSessionWithPrincipal(response, request)
	if !ok {
		return
	}
	if !requireRecentMFA(response, session) {
		return
	}
	if err := h.repositories.SetVisibilityPolicy(request.Context(), session.UserID,
		repositories.VisibilityPolicy(payload.Policy)); err != nil {
		writeRepositoryError(response, err)
		return
	}
	writeNoContent(response)
}

func requireRecentMFA(response http.ResponseWriter, session sessions.Session) bool {
	if session.Level != sessions.LevelMFA {
		writeAPIError(response, http.StatusForbidden, "mfa_required")
		return false
	}
	if session.MFAAuthenticatedAt == nil {
		writeAPIError(response, http.StatusForbidden, "reauthentication_required")
		return false
	}
	mfaAge := time.Since(*session.MFAAuthenticatedAt)
	if mfaAge < 0 || mfaAge >= workspaceCreationMFAMaxAge {
		writeAPIError(response, http.StatusForbidden, "reauthentication_required")
		return false
	}
	return true
}

func (h *authHTTP) logout(response http.ResponseWriter, request *http.Request) {
	if !h.requireCanonicalRequest(response, request) {
		return
	}
	bearerToken, found, err := uniqueCookie(request, sessionCookieName)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if !found {
		clearSessionCookies(response)
		writeNoContent(response)
		return
	}
	csrfToken, csrfFound, err := uniqueCookie(request, csrfCookieName)
	if err != nil || !csrfFound || !requestCSRFHeaderMatches(request, csrfToken) {
		writeAPIError(response, http.StatusForbidden, "csrf_failed")
		return
	}
	_, validationErr := h.service.ValidateWithCSRF(request.Context(), bearerToken, csrfToken)
	if validationErr != nil && !errors.Is(validationErr, sessions.ErrSessionUnavailable) {
		writeServiceError(response, validationErr)
		return
	}
	if err := h.service.Logout(request.Context(), bearerToken); err != nil {
		writeServiceError(response, err)
		return
	}
	clearSessionCookies(response)
	writeNoContent(response)
}

func (h *authHTTP) validateBrowserSession(
	response http.ResponseWriter,
	request *http.Request,
) (string, string, bool) {
	bearerToken, csrfToken, _, ok := h.validateBrowserSessionWithPrincipal(response, request)
	return bearerToken, csrfToken, ok
}

func (h *authHTTP) validateBrowserSessionWithPrincipal(
	response http.ResponseWriter,
	request *http.Request,
) (string, string, sessions.Session, bool) {
	bearerToken, found, err := uniqueCookie(request, sessionCookieName)
	if err != nil || !found {
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
		return "", "", sessions.Session{}, false
	}
	csrfToken, found, err := uniqueCookie(request, csrfCookieName)
	if err != nil || !found || !requestCSRFHeaderMatches(request, csrfToken) {
		writeAPIError(response, http.StatusForbidden, "csrf_failed")
		return "", "", sessions.Session{}, false
	}
	session, err := h.service.ValidateWithCSRF(request.Context(), bearerToken, csrfToken)
	if err != nil {
		writeServiceError(response, err)
		return "", "", sessions.Session{}, false
	}
	return bearerToken, csrfToken, session, true
}

func (h *authHTTP) validateAuthenticatedSession(
	response http.ResponseWriter,
	request *http.Request,
) (sessions.Session, bool) {
	bearerToken, found, err := uniqueCookie(request, sessionCookieName)
	if err != nil || !found {
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
		return sessions.Session{}, false
	}
	session, err := h.service.ValidateSession(request.Context(), bearerToken)
	if err != nil {
		writeServiceError(response, err)
		return sessions.Session{}, false
	}
	if session.Level != sessions.LevelStandard && session.Level != sessions.LevelMFA {
		writeAPIError(response, http.StatusForbidden, "authentication_incomplete")
		return sessions.Session{}, false
	}
	return session, true
}

func (h *authHTTP) requireCanonicalRequest(response http.ResponseWriter, request *http.Request) bool {
	originValues := request.Header.Values("Origin")
	if len(originValues) != 1 {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return false
	}
	origin, err := normalizeOrigin(originValues[0])
	if err != nil || origin != h.canonicalOrigin {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return false
	}
	requestOrigin, err := normalizeOrigin("https://" + request.Host)
	if err != nil || requestOrigin != h.canonicalOrigin {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return false
	}
	if !requestUsesHTTPS(request, h.trustedProxies) {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return false
	}
	return true
}

func requestUsesHTTPS(request *http.Request, trustedProxies []netip.Prefix) bool {
	if request.TLS != nil {
		return true
	}
	peer, err := parseAddressWithOptionalPort(request.RemoteAddr)
	if err != nil || !isTrustedProxy(peer, trustedProxies) {
		return false
	}
	forwardedProtocols := request.Header.Values("X-Forwarded-Proto")
	return len(forwardedProtocols) == 1 && strings.EqualFold(strings.TrimSpace(forwardedProtocols[0]), "https")
}

func decodeJSONBody[T any](response http.ResponseWriter, request *http.Request, destination *T) int {
	return decodeJSONBodyLimit(response, request, destination, maxAuthRequestBytes)
}

func decodeJSONBodyLimit[T any](response http.ResponseWriter, request *http.Request, destination *T, maxBytes int64) int {
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return http.StatusUnsupportedMediaType
	}
	if charset, exists := parameters["charset"]; exists && !strings.EqualFold(charset, "utf-8") {
		return http.StatusUnsupportedMediaType
	}
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxBytes))
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return http.StatusRequestEntityTooLarge
		}
		return http.StatusBadRequest
	}
	trimmedBody := bytes.TrimSpace(body)
	if len(trimmedBody) == 0 || trimmedBody[0] != '{' || !hasUniqueJSONKeys(trimmedBody) {
		return http.StatusBadRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmedBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return http.StatusBadRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return http.StatusBadRequest
	}
	return 0
}

func hasUniqueJSONKeys(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return false
		}
		key, ok := keyToken.(string)
		if !ok {
			return false
		}
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
	}
	closingToken, err := decoder.Token()
	if err != nil || closingToken != json.Delim('}') {
		return false
	}
	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}

func requestErrorCode(status int) string {
	if status == http.StatusUnsupportedMediaType {
		return "unsupported_media_type"
	}
	if status == http.StatusRequestEntityTooLarge {
		return "request_too_large"
	}
	return "invalid_request"
}

func parseWorkspaceListQuery(request *http.Request) (string, int, bool) {
	const defaultPageSize = 50
	query := request.URL.Query()
	for name, values := range query {
		if (name != "after_workspace_id" && name != "limit") || len(values) != 1 {
			return "", 0, false
		}
	}
	afterWorkspaceID := ""
	if values, exists := query["after_workspace_id"]; exists {
		afterWorkspaceID = values[0]
		if strings.TrimSpace(afterWorkspaceID) == "" {
			return "", 0, false
		}
	}
	pageSize := defaultPageSize
	if values, exists := query["limit"]; exists {
		parsedPageSize, err := strconv.Atoi(values[0])
		if err != nil || parsedPageSize < 1 || parsedPageSize > 100 {
			return "", 0, false
		}
		pageSize = parsedPageSize
	}
	return afterWorkspaceID, pageSize, true
}

func parseRepositoryListQuery(request *http.Request) (string, int, bool) {
	const defaultPageSize = 50
	query := request.URL.Query()
	for name, values := range query {
		if (name != "after_repository_id" && name != "limit") || len(values) != 1 {
			return "", 0, false
		}
	}
	afterRepositoryID := ""
	if values, exists := query["after_repository_id"]; exists {
		afterRepositoryID = values[0]
		if strings.TrimSpace(afterRepositoryID) == "" {
			return "", 0, false
		}
	}
	pageSize := defaultPageSize
	if values, exists := query["limit"]; exists {
		parsedPageSize, err := strconv.Atoi(values[0])
		if err != nil || parsedPageSize < 1 || parsedPageSize > 100 {
			return "", 0, false
		}
		pageSize = parsedPageSize
	}
	return afterRepositoryID, pageSize, true
}

func parseRepositoryGrantListQuery(request *http.Request) (string, int, bool) {
	const defaultPageSize = 50
	query := request.URL.Query()
	for name, values := range query {
		if (name != "after_grant_id" && name != "limit") || len(values) != 1 {
			return "", 0, false
		}
	}
	afterGrantID := ""
	if values, exists := query["after_grant_id"]; exists {
		afterGrantID = values[0]
		if strings.TrimSpace(afterGrantID) == "" {
			return "", 0, false
		}
	}
	pageSize := defaultPageSize
	if values, exists := query["limit"]; exists {
		parsedPageSize, err := strconv.Atoi(values[0])
		if err != nil || parsedPageSize < 1 || parsedPageSize > 100 {
			return "", 0, false
		}
		pageSize = parsedPageSize
	}
	return afterGrantID, pageSize, true
}

func writeWorkspaceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, workspaces.ErrUnauthenticated):
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
	case errors.Is(err, workspaces.ErrForbidden):
		writeAPIError(response, http.StatusForbidden, "forbidden")
	case errors.Is(err, workspaces.ErrInvalidSlug),
		errors.Is(err, workspaces.ErrInvalidName),
		errors.Is(err, workspaces.ErrInvalidWorkspaceID),
		errors.Is(err, workspaces.ErrInvalidMembershipRole),
		errors.Is(err, workspaces.ErrInvalidCursor),
		errors.Is(err, workspaces.ErrInvalidPageSize):
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, workspaces.ErrSlugConflict):
		writeAPIError(response, http.StatusConflict, "workspace_slug_conflict")
	case errors.Is(err, workspaces.ErrLastOwner):
		writeAPIError(response, http.StatusConflict, "last_owner_required")
	case errors.Is(err, workspaces.ErrSelfElevation):
		writeAPIError(response, http.StatusForbidden, "self_elevation_forbidden")
	case errors.Is(err, workspaces.ErrMembershipUnavailable):
		writeAPIError(response, http.StatusNotFound, "membership_unavailable")
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
	}
}

func writeRepositoryError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repositories.ErrUnauthenticated):
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
	case errors.Is(err, repositories.ErrForbidden):
		writeAPIError(response, http.StatusForbidden, "forbidden")
	case errors.Is(err, repositories.ErrInvalidWorkspaceID),
		errors.Is(err, repositories.ErrInvalidFormat),
		errors.Is(err, repositories.ErrInvalidQuota),
		errors.Is(err, repositories.ErrInvalidPersonalTokenRequest),
		errors.Is(err, repositories.ErrInvalidJobCursor),
		errors.Is(err, repositories.ErrInvalidJobRequest),
		errors.Is(err, repositories.ErrInvalidRepositoryID),
		errors.Is(err, repositories.ErrInvalidSlug),
		errors.Is(err, repositories.ErrInvalidName),
		errors.Is(err, repositories.ErrInvalidPageSize),
		errors.Is(err, repositories.ErrInvalidGrantRole),
		errors.Is(err, repositories.ErrInvalidGrantCursor),
		errors.Is(err, repositories.ErrInvalidGrantPageSize),
		errors.Is(err, repositories.ErrInvalidVisibility),
		errors.Is(err, repositories.ErrInvalidVisibilityPolicy):
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, repositories.ErrSlugConflict):
		writeAPIError(response, http.StatusConflict, "repository_slug_conflict")
	case errors.Is(err, repositories.ErrFormatMismatch):
		writeAPIError(response, http.StatusConflict, "repository_format_mismatch")
	case errors.Is(err, repositories.ErrReviewRequired):
		writeAPIError(response, http.StatusConflict, "human_review_required")
	case errors.Is(err, repositories.ErrQuotaRevision):
		writeAPIError(response, http.StatusConflict, "logical_quota_revision_conflict")
	case errors.Is(err, repositories.ErrDeadJobConflict):
		writeAPIError(response, http.StatusConflict, "dead_job_revision_conflict")
	case errors.Is(err, repositories.ErrRecoveryJobConflict):
		writeAPIError(response, http.StatusConflict, "recovery_job_revision_conflict")
	case errors.Is(err, repositories.ErrVisibilityNotAllowed):
		writeAPIError(response, http.StatusForbidden, "visibility_not_permitted")
	case errors.Is(err, repositories.ErrPublicConfirmation):
		writeAPIError(response, http.StatusPreconditionFailed, "public_visibility_confirmation_required")
	case errors.Is(err, repositories.ErrRepositoryUnavailable), errors.Is(err, repositories.ErrUserUnavailable), errors.Is(err, repositories.ErrPersonalTokenUnavailable), errors.Is(err, repositories.ErrCargoWriteTokenUnavailable):
		writeAPIError(response, http.StatusNotFound, "resource_unavailable")
	case errors.Is(err, repositories.ErrMembershipUnavailable):
		writeAPIError(response, http.StatusNotFound, "membership_unavailable")
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
	}
}

func writeArtifactError(response http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	switch {
	case errors.Is(err, repositories.ErrUnauthenticated):
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
	case errors.Is(err, repositories.ErrForbidden):
		writeAPIError(response, http.StatusForbidden, "forbidden")
	case errors.Is(err, repositories.ErrMembershipUnavailable):
		writeAPIError(response, http.StatusForbidden, "forbidden")
	case errors.Is(err, repositories.ErrUserUnavailable):
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
	case errors.Is(err, repositories.ErrFormatMismatch):
		writeAPIError(response, http.StatusConflict, "repository_format_mismatch")
	case errors.Is(err, repositories.ErrReviewRequired):
		writeAPIError(response, http.StatusConflict, "human_review_required")
	case errors.Is(err, artifacts.ErrInvalidCollectionName),
		errors.Is(err, artifacts.ErrInvalidVersionLabel),
		errors.Is(err, artifacts.ErrInvalidArtifactPath),
		errors.Is(err, artifacts.ErrInvalidContentType),
		errors.Is(err, artifacts.ErrInvalidArtifactSize),
		errors.Is(err, artifacts.ErrInvalidDigest),
		errors.Is(err, repositories.ErrInvalidWorkspaceID),
		errors.Is(err, repositories.ErrInvalidRepositoryID):
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, artifacts.ErrArtifactNotFound),
		errors.Is(err, artifacts.ErrUploadNotFound),
		errors.Is(err, artifacts.ErrDownloadTicketUnavailable),
		errors.Is(err, repositories.ErrRepositoryUnavailable):
		writeAPIError(response, http.StatusNotFound, "resource_unavailable")
	case errors.Is(err, artifacts.ErrVersionConflict),
		errors.Is(err, artifacts.ErrPathConflict),
		errors.Is(err, artifacts.ErrUploadStateConflict),
		errors.Is(err, artifacts.ErrVersionIncomplete),
		errors.Is(err, artifacts.ErrVersionEmpty):
		writeAPIError(response, http.StatusConflict, "artifact_state_conflict")
	case errors.Is(err, artifacts.ErrUploadExpired):
		writeAPIError(response, http.StatusGone, "upload_session_expired")
	case errors.Is(err, artifacts.ErrLogicalQuotaExceeded):
		writeAPIError(response, http.StatusConflict, "logical_quota_exceeded")
	case errors.Is(err, artifacts.ErrUploadTooLarge), errors.As(err, &maxBytesError):
		writeAPIError(response, http.StatusRequestEntityTooLarge, "request_too_large")
	case errors.Is(err, artifacts.ErrUploadDigestMismatch):
		writeAPIError(response, http.StatusUnprocessableEntity, "artifact_digest_mismatch")
	case errors.Is(err, artifacts.ErrUploadSizeMismatch):
		writeAPIError(response, http.StatusUnprocessableEntity, "artifact_size_mismatch")
	case errors.Is(err, artifacts.ErrInvalidRange):
		writeAPIError(response, http.StatusRequestedRangeNotSatisfiable, "invalid_range")
	case errors.Is(err, artifacts.ErrUploadCapacity):
		response.Header().Set("Retry-After", "1")
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
	}
}

func toArtifactVersionResponse(artifact artifacts.ArtifactVersion) artifactVersionResponse {
	result := artifactVersionResponse{
		ArtifactVersionID: artifact.ID,
		WorkspaceID:       artifact.WorkspaceID,
		RepositoryID:      artifact.RepositoryID,
		Collection:        artifact.Collection,
		Version:           artifact.Version,
		Status:            artifact.Status,
		Files:             make([]artifactFileResponse, 0, len(artifact.Files)),
	}
	if artifact.PublishedAt != nil {
		result.PublishedAt = artifact.PublishedAt.UTC().Format(time.RFC3339Nano)
	}
	for _, file := range artifact.Files {
		result.Files = append(result.Files, artifactFileResponse{
			ArtifactFileID: file.ID,
			Path:           file.Path,
			ContentType:    file.ContentType,
			Size:           file.Size,
			SHA256:         file.SHA256,
		})
	}
	return result
}

func writeServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrRejected), errors.Is(err, sessions.ErrSessionUnavailable):
		writeAPIError(response, http.StatusUnauthorized, "authentication_failed")
	case errors.Is(err, auth.ErrRateLimited):
		writeAPIError(response, http.StatusTooManyRequests, "rate_limited")
	case errors.Is(err, sessions.ErrCSRF):
		writeAPIError(response, http.StatusForbidden, "csrf_failed")
	case errors.Is(err, auth.ErrInvalidClientAddress):
		writeAPIError(response, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, auth.ErrEnrollmentUnavailable):
		writeAPIError(response, http.StatusConflict, "mfa_enrollment_unavailable")
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
	}
}

func writeAPIError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, apiErrorResponse{Error: code})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	setAuthResponseHeaders(response)
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		return
	}
}

func writeNoContent(response http.ResponseWriter) {
	setAuthResponseHeaders(response)
	response.WriteHeader(http.StatusNoContent)
}

func setAuthResponseHeaders(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
}

func setSessionCookies(response http.ResponseWriter, credentials sessions.Credentials) {
	http.SetCookie(response, &http.Cookie{
		Name:     sessionCookieName,
		Value:    credentials.BearerToken,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(response, &http.Cookie{
		Name:     csrfCookieName,
		Value:    credentials.CSRFToken,
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookies(response http.ResponseWriter) {
	http.SetCookie(response, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(response, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func uniqueCookie(request *http.Request, name string) (string, bool, error) {
	value := ""
	found := false
	for _, cookie := range request.Cookies() {
		if cookie.Name != name {
			continue
		}
		if found {
			return "", false, errors.New("duplicate authentication cookie")
		}
		found = true
		value = cookie.Value
	}
	if !found || value == "" {
		return "", found, nil
	}
	return value, true, nil
}

func requestCSRFHeaderMatches(request *http.Request, cookieValue string) bool {
	values := request.Header.Values(csrfHeaderName)
	if len(values) != 1 || values[0] == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(values[0]), []byte(cookieValue)) == 1
}

func normalizeOrigin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || strings.ContainsAny(raw, "?#") || !strings.EqualFold(parsed.Scheme, "https") {
		return "", errors.New("origin must be an HTTPS origin without a path")
	}
	if strings.HasSuffix(parsed.Host, ":") || strings.Contains(parsed.Host, "%") {
		return "", errors.New("origin authority is invalid")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", errors.New("origin host is invalid")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address.Zone() != "" {
			return "", errors.New("origin host zone is not supported")
		}
		host = address.String()
	} else if !validDNSHost(host) {
		return "", errors.New("origin host is invalid")
	}

	portValue := parsed.Port()
	if portValue == "" {
		if strings.Contains(host, ":") {
			return "https://[" + host + "]", nil
		}
		return "https://" + host, nil
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("origin port is invalid")
	}
	if port == 443 {
		if strings.Contains(host, ":") {
			return "https://[" + host + "]", nil
		}
		return "https://" + host, nil
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func validDNSHost(host string) bool {
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func clientAddress(request *http.Request, trustedProxies []netip.Prefix) (string, error) {
	peer, err := parseAddressWithOptionalPort(request.RemoteAddr)
	if err != nil {
		return "", errors.New("peer network address is invalid")
	}
	if !isTrustedProxy(peer, trustedProxies) {
		return peer.String(), nil
	}
	forwardedValues := request.Header.Values("X-Forwarded-For")
	if len(forwardedValues) == 0 {
		return peer.String(), nil
	}
	forwardedHeader := strings.Join(forwardedValues, ",")
	if len(forwardedHeader) > maxForwardedForHeaderBytes {
		return "", errors.New("forwarded address chain is too long")
	}
	forwarded := strings.Split(forwardedHeader, ",")
	if len(forwarded) > 16 {
		return "", errors.New("forwarded address chain is too long")
	}
	addresses := make([]netip.Addr, 0, len(forwarded))
	for _, value := range forwarded {
		address, err := parseAddressWithOptionalPort(strings.TrimSpace(value))
		if err != nil {
			return "", errors.New("forwarded address chain is invalid")
		}
		addresses = append(addresses, address)
	}
	client := peer
	for index := len(addresses) - 1; index >= 0; index-- {
		if !isTrustedProxy(client, trustedProxies) {
			break
		}
		client = addresses[index]
	}
	return client.String(), nil
}

func parseAddressWithOptionalPort(value string) (netip.Addr, error) {
	if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
		return address.Unmap(), nil
	}
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("network address is invalid: %w", err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, errors.New("network address is invalid")
	}
	return address.Unmap(), nil
}

func isTrustedProxy(address netip.Addr, trustedProxies []netip.Prefix) bool {
	for _, proxy := range trustedProxies {
		if proxy.Contains(address) {
			return true
		}
	}
	return false
}
