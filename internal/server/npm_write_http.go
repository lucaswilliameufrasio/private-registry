package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/npm"
	"private-registry/internal/repositories"
)

type NPMWriteProtocolConfig struct {
	StagingDirectory string
	MaxDocumentBytes int64
	MaxArchiveBytes  int64
	MaxConcurrent    int
}

type npmWriteProtocol struct {
	staging     string
	maxDocument int64
	maxArchive  int64
	slots       chan struct{}
}

func newNPMWriteProtocol(cfg *NPMWriteProtocolConfig) (*npmWriteProtocol, error) {
	if cfg == nil {
		return nil, nil
	}
	if !filepath.IsAbs(cfg.StagingDirectory) || cfg.MaxDocumentBytes < 1 || cfg.MaxDocumentBytes > 128<<20 || cfg.MaxArchiveBytes < 1 || cfg.MaxArchiveBytes > 64<<20 || cfg.MaxConcurrent < 1 || cfg.MaxConcurrent > 16 {
		return nil, errors.New("npm write protocol configuration is invalid")
	}
	info, err := os.Lstat(cfg.StagingDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("npm write protocol staging directory must be private")
	}
	return &npmWriteProtocol{staging: cfg.StagingDirectory, maxDocument: cfg.MaxDocumentBytes, maxArchive: cfg.MaxArchiveBytes, slots: make(chan struct{}, cfg.MaxConcurrent)}, nil
}

// npmPublish is experimental and opt-in. A native
// success means both publication and the requested initial tags committed.
func (h *authHTTP) npmPublish(response http.ResponseWriter, request *http.Request) {
	workspace, repository, ok := h.npmReadScope(response, request)
	if !ok {
		return
	}
	token, ok := h.npmCredential(response, request, workspace, repository, true)
	if !ok {
		return
	}
	if strings.Contains(strings.ToLower(request.URL.EscapedPath()), "%25") {
		npmReadError(response, http.StatusBadRequest, "invalid publication")
		return
	}
	name, err := url.PathUnescape(chi.URLParam(request, "*"))
	if err != nil || npm.ValidatePackageName(name) != nil {
		npmReadError(response, http.StatusBadRequest, "invalid publication")
		return
	}
	select {
	case h.npmWriteProtocol.slots <- struct{}{}:
		defer func() { <-h.npmWriteProtocol.slots }()
	default:
		npmReadError(response, http.StatusServiceUnavailable, "publication capacity unavailable")
		return
	}
	request, cancel, ok := goRequestContext(response, request, true)
	if !ok {
		return
	}
	defer cancel()
	stage, err := os.CreateTemp(h.npmWriteProtocol.staging, "npm-document-*")
	if err != nil {
		npmReadError(response, http.StatusServiceUnavailable, "publication staging unavailable")
		return
	}
	stagePath := stage.Name()
	defer func() { _ = os.Remove(stagePath) }()
	body := http.MaxBytesReader(response, request.Body, h.npmWriteProtocol.maxDocument)
	document, readErr := npm.ReadPublishDocument(request.Context(), body, stage, name, h.npmWriteProtocol.maxDocument, h.npmWriteProtocol.maxArchive)
	closeErr := stage.Close()
	if readErr != nil || closeErr != nil {
		npmReadError(response, http.StatusBadRequest, "invalid publication")
		return
	}
	file, err := os.Open(stagePath)
	if err != nil {
		npmReadError(response, http.StatusServiceUnavailable, "publication staging unavailable")
		return
	}
	digest := sha256.New()
	count, hashErr := io.Copy(digest, io.LimitReader(file, document.Size+1))
	closeErr = file.Close()
	if hashErr != nil || closeErr != nil || count != document.Size {
		npmReadError(response, http.StatusServiceUnavailable, "publication staging unavailable")
		return
	}
	metadata := sha256.Sum256(document.Manifest)
	reservation, err := h.npmReservations.Reserve(request.Context(), token, workspace, repository, npm.ReservationRequest{Name: document.Name, Version: document.Version, TarballSHA256: hex.EncodeToString(digest.Sum(nil)), TarballSize: document.Size, MetadataSHA256: hex.EncodeToString(metadata[:])})
	if err != nil {
		h.writeNPMPublishError(response, err)
		return
	}
	file, err = os.Open(stagePath)
	if err != nil {
		npmReadError(response, http.StatusServiceUnavailable, "publication staging unavailable")
		return
	}
	receiveErr := h.npmReceipts.Receive(request.Context(), token, workspace, repository, reservation.ID, document, file)
	closeErr = file.Close()
	if closeErr != nil {
		npmReadError(response, http.StatusServiceUnavailable, "publication staging unavailable")
		return
	}
	if receiveErr != nil && receiveErr != npm.ErrReservationUnavailable {
		h.writeNPMPublishError(response, receiveErr)
		return
	}
	if _, err := h.npmReservations.PublishReceiptWithInitialTags(request.Context(), token, workspace, repository, reservation.ID, document.Tags); err != nil {
		h.writeNPMPublishError(response, err)
		return
	}
	if err := os.Remove(stagePath); err != nil {
		npmReadError(response, http.StatusServiceUnavailable, "publication staging cleanup failed")
		return
	}
	npmReadJSON(response, http.StatusCreated, map[string]bool{"ok": true})
}

func (h *authHTTP) writeNPMPublishError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repositories.ErrNPMWriteTokenUnavailable):
		npmReadError(response, http.StatusUnauthorized, "authentication required")
	case errors.Is(err, repositories.ErrForbidden), errors.Is(err, repositories.ErrMembershipUnavailable):
		npmReadError(response, http.StatusForbidden, "access denied")
	case errors.Is(err, repositories.ErrReviewRequired):
		npmReadError(response, http.StatusConflict, "human review required; publication is pending")
	case errors.Is(err, npm.ErrReservationConflict), errors.Is(err, npm.ErrReservationQuota), errors.Is(err, npm.ErrTagConflict), errors.Is(err, npm.ErrTagUnavailable):
		npmReadError(response, http.StatusConflict, "publication unavailable")
	default:
		npmReadError(response, http.StatusServiceUnavailable, "registry temporarily unavailable")
	}
}
