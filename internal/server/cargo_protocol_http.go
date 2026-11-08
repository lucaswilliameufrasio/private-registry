package server

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"private-registry/internal/authattempts"
	"private-registry/internal/cargo"
	"private-registry/internal/repositories"
)

// CargoProtocolConfig is explicitly opt-in. Production wiring remains closed
// until the full protocol, recovery and client acceptance gates are satisfied.
type CargoProtocolConfig struct {
	StagingDirectory string
	MaxArchiveBytes  int64
	MaxConcurrent    int
}

type cargoProtocol struct {
	staging string
	maxSize int64
	slots   chan struct{}
}

func newCargoProtocol(config *CargoProtocolConfig) (*cargoProtocol, error) {
	if config == nil {
		return nil, nil
	}
	if !filepath.IsAbs(config.StagingDirectory) || config.MaxArchiveBytes < 1 || config.MaxArchiveBytes > 500<<20 || config.MaxConcurrent < 1 || config.MaxConcurrent > 16 {
		return nil, errors.New("Cargo protocol configuration is invalid")
	}
	info, err := os.Lstat(config.StagingDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Cargo protocol staging directory must be private")
	}
	return &cargoProtocol{staging: config.StagingDirectory, maxSize: config.MaxArchiveBytes, slots: make(chan struct{}, config.MaxConcurrent)}, nil
}

func (h *authHTTP) registerCargoProtocolRoutes(router chi.Router) {
	base := "/cargo/{workspaceID}/{repositoryID}"
	router.Get(base+"/index/config.json", h.cargoConfig)
	router.Get(base+"/index/*", h.cargoIndex)
	router.Get(base+"/api/v1/crates/{crate}/{version}/download", h.cargoDownload)
	router.Put(base+"/api/v1/crates/new", h.cargoPublish)
	router.Delete(base+"/api/v1/crates/{crate}/{version}/yank", h.cargoYank)
	router.Put(base+"/api/v1/crates/{crate}/{version}/unyank", h.cargoUnyank)
}

func cargoProtocolError(response http.ResponseWriter, status int, detail string) {
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	writeJSON(response, status, map[string]any{"errors": []map[string]string{{"detail": detail}}})
}

func (h *authHTTP) cargoProtocolScope(response http.ResponseWriter, request *http.Request) (string, string, bool) {
	origin, err := normalizeOrigin("https://" + request.Host)
	workspace, repository := chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID")
	wid, werr := uuid.Parse(workspace)
	rid, rerr := uuid.Parse(repository)
	if err != nil || origin != h.canonicalOrigin || !requestUsesHTTPS(request, h.trustedProxies) || request.URL.RawQuery != "" || werr != nil || rerr != nil || wid.String() != workspace || rid.String() != repository || wid == uuid.Nil || rid == uuid.Nil {
		cargoProtocolError(response, http.StatusForbidden, "registry unavailable")
		return "", "", false
	}
	return workspace, repository, true
}

// Cargo uses the credential as the raw Authorization header, not a Bearer
// scheme. Both read and write attempts use the shared source rate limiter.
func (h *authHTTP) cargoCredential(response http.ResponseWriter, request *http.Request, workspace, repository string, write bool) (string, string, bool) {
	select {
	case h.personalTokenSlots <- struct{}{}:
		defer func() { <-h.personalTokenSlots }()
	default:
		cargoProtocolError(response, http.StatusServiceUnavailable, "registry temporarily unavailable")
		return "", "", false
	}
	source, err := clientAddress(request, h.trustedProxies)
	if err != nil {
		cargoProtocolError(response, http.StatusBadRequest, "invalid request")
		return "", "", false
	}
	retryAfter, err := h.service.BeginPersonalToken(request.Context(), source)
	if err != nil {
		if errors.Is(err, authattempts.ErrRateLimited) {
			seconds := int64((retryAfter + time.Second - 1) / time.Second)
			if seconds < 1 {
				seconds = 1
			}
			response.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
			cargoProtocolError(response, http.StatusTooManyRequests, "rate limited")
		} else {
			cargoProtocolError(response, http.StatusServiceUnavailable, "registry temporarily unavailable")
		}
		return "", "", false
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 128 || strings.TrimSpace(values[0]) != values[0] || strings.ContainsAny(values[0], " \t\r\n") {
		cargoProtocolError(response, http.StatusUnauthorized, "authentication required")
		return "", "", false
	}
	token := values[0]
	var actor string
	if write {
		err = h.repositories.WithCargoWriteTokenTransaction(request.Context(), token, workspace, repository, func(_ *sql.Tx, user string) error {
			actor = user
			return nil
		})
	} else {
		actor, err = h.repositories.VerifyPersonalReadToken(request.Context(), token, workspace, repository)
	}
	if errors.Is(err, repositories.ErrCargoWriteTokenUnavailable) || errors.Is(err, repositories.ErrPersonalTokenUnavailable) {
		cargoProtocolError(response, http.StatusUnauthorized, "authentication required")
		return "", "", false
	}
	if err != nil || h.service.CompletePersonalToken(request.Context(), source) != nil {
		cargoProtocolError(response, http.StatusServiceUnavailable, "registry temporarily unavailable")
		return "", "", false
	}
	return token, actor, true
}

func (h *authHTTP) cargoConfig(response http.ResponseWriter, request *http.Request) {
	workspace, repository, ok := h.cargoProtocolScope(response, request)
	if !ok {
		return
	}
	base := h.canonicalOrigin + "/cargo/" + workspace + "/" + repository
	response.Header().Set("Cache-Control", "private, no-store")
	writeJSON(response, http.StatusOK, map[string]any{"dl": base + "/api/v1/crates/{crate}/{version}/download", "api": base, "auth-required": true})
}

func (h *authHTTP) cargoIndex(response http.ResponseWriter, request *http.Request) {
	workspace, repository, ok := h.cargoProtocolScope(response, request)
	if !ok {
		return
	}
	token, _, ok := h.cargoCredential(response, request, workspace, repository, false)
	if !ok {
		return
	}
	indexPath := chi.URLParam(request, "*")
	name := path.Base(indexPath)
	expected, err := cargo.SparseIndexPath(name)
	if err != nil || expected != indexPath {
		cargoProtocolError(response, http.StatusNotFound, "package unavailable")
		return
	}
	contents, err := h.cargoReservations.ReadSparseIndexWithToken(request.Context(), token, workspace, repository, name)
	if err != nil {
		h.writeCargoProtocolError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Vary", "Authorization")
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	response.Header().Set("Content-Length", strconv.Itoa(len(contents)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(contents)
}

func (h *authHTTP) cargoDownload(response http.ResponseWriter, request *http.Request) {
	workspace, repository, ok := h.cargoProtocolScope(response, request)
	if !ok {
		return
	}
	token, _, ok := h.cargoCredential(response, request, workspace, repository, false)
	if !ok {
		return
	}
	deadline := time.Now().Add(goRequestTimeout)
	if err := http.NewResponseController(response).SetWriteDeadline(deadline); err != nil {
		cargoProtocolError(response, http.StatusServiceUnavailable, "registry temporarily unavailable")
		return
	}
	defer func() { _ = http.NewResponseController(response).SetWriteDeadline(time.Time{}) }()
	ctx, cancel := context.WithDeadline(request.Context(), deadline)
	defer cancel()
	reader, size, err := h.cargoReceipts.OpenPublishedArchiveWithToken(ctx, token, workspace, repository, chi.URLParam(request, "crate"), chi.URLParam(request, "version"))
	if err != nil {
		h.writeCargoProtocolError(response, err)
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

func (h *authHTTP) cargoPublish(response http.ResponseWriter, request *http.Request) {
	workspace, repository, ok := h.cargoProtocolScope(response, request)
	if !ok {
		return
	}
	token, _, ok := h.cargoCredential(response, request, workspace, repository, true)
	if !ok {
		return
	}
	select {
	case h.cargoProtocol.slots <- struct{}{}:
		defer func() { <-h.cargoProtocol.slots }()
	default:
		cargoProtocolError(response, http.StatusServiceUnavailable, "publication capacity unavailable")
		return
	}
	request, cancel, ok := goRequestContext(response, request, true)
	if !ok {
		return
	}
	defer cancel()
	stage, err := os.CreateTemp(h.cargoProtocol.staging, "cargo-frame-*")
	if err != nil {
		cargoProtocolError(response, http.StatusServiceUnavailable, "publication staging unavailable")
		return
	}
	stagePath := stage.Name()
	defer func() { _ = os.Remove(stagePath) }()
	body := http.MaxBytesReader(response, request.Body, h.cargoProtocol.maxSize+(16<<20)+8)
	frame, readErr := cargo.ReadPublishFrame(request.Context(), body, stage, 16<<20, h.cargoProtocol.maxSize)
	closeErr := stage.Close()
	if readErr != nil || closeErr != nil {
		cargoProtocolError(response, http.StatusBadRequest, "invalid publication")
		return
	}
	reservation, err := h.cargoReservations.Reserve(request.Context(), token, workspace, repository, frame)
	if err != nil {
		h.writeCargoProtocolError(response, err)
		return
	}
	file, err := os.Open(stagePath)
	if err != nil {
		cargoProtocolError(response, http.StatusServiceUnavailable, "publication staging unavailable")
		return
	}
	receiveErr := h.cargoReceipts.Receive(request.Context(), token, workspace, repository, reservation.ID, frame, file)
	closeErr = file.Close()
	if closeErr != nil {
		cargoProtocolError(response, http.StatusServiceUnavailable, "publication staging unavailable")
		return
	}
	// Only a plain unavailable result can represent an already uploaded
	// receipt. Joined cleanup errors must never be converted into success.
	if receiveErr != nil && receiveErr != cargo.ErrReservationUnavailable {
		h.writeCargoProtocolError(response, receiveErr)
		return
	}
	if _, err := h.cargoReservations.PublishReceipt(request.Context(), token, workspace, repository, reservation.ID); err != nil {
		h.writeCargoProtocolError(response, err)
		return
	}
	if err := os.Remove(stagePath); err != nil {
		cargoProtocolError(response, http.StatusServiceUnavailable, "publication staging cleanup failed")
		return
	}
	response.Header().Set("Cache-Control", "private, no-store")
	writeJSON(response, http.StatusOK, map[string]any{"warnings": map[string]any{"invalid_categories": []string{}, "invalid_badges": []string{}, "other": []string{}}})
}

func (h *authHTTP) cargoYank(response http.ResponseWriter, request *http.Request) {
	h.setCargoYank(response, request, true)
}

func (h *authHTTP) cargoUnyank(response http.ResponseWriter, request *http.Request) {
	h.setCargoYank(response, request, false)
}

func (h *authHTTP) setCargoYank(response http.ResponseWriter, request *http.Request, yanked bool) {
	workspace, repository, ok := h.cargoProtocolScope(response, request)
	if !ok {
		return
	}
	token, _, ok := h.cargoCredential(response, request, workspace, repository, true)
	if !ok {
		return
	}
	if err := h.cargoReservations.SetYanked(request.Context(), token, workspace, repository, chi.URLParam(request, "crate"), chi.URLParam(request, "version"), yanked); err != nil {
		h.writeCargoProtocolError(response, err)
		return
	}
	response.Header().Set("Cache-Control", "private, no-store")
	writeJSON(response, http.StatusOK, map[string]bool{"ok": true})
}

func (h *authHTTP) writeCargoProtocolError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repositories.ErrCargoWriteTokenUnavailable), errors.Is(err, repositories.ErrPersonalTokenUnavailable):
		cargoProtocolError(response, http.StatusUnauthorized, "authentication required")
	case errors.Is(err, repositories.ErrForbidden), errors.Is(err, repositories.ErrMembershipUnavailable):
		cargoProtocolError(response, http.StatusForbidden, "access denied")
	case errors.Is(err, cargo.ErrPackageUnavailable), errors.Is(err, cargo.ErrReservationUnavailable):
		cargoProtocolError(response, http.StatusNotFound, "package unavailable")
	case errors.Is(err, repositories.ErrReviewRequired):
		cargoProtocolError(response, http.StatusConflict, "human review required; publication is pending")
	case errors.Is(err, cargo.ErrReservationConflict), errors.Is(err, cargo.ErrReservationQuota):
		cargoProtocolError(response, http.StatusConflict, "publication unavailable")
	default:
		cargoProtocolError(response, http.StatusServiceUnavailable, "registry temporarily unavailable")
	}
}
