package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"private-registry/internal/pub"
	"private-registry/internal/repositories"
)

type PubWriteProtocolConfig struct {
	StagingDirectory string
	MaxArchiveBytes  int64
	MaxConcurrent    int
	Limits           pub.ArchiveLimits
}

type pubWriteProtocol struct {
	staging    string
	maxArchive int64
	limits     pub.ArchiveLimits
	slots      chan struct{}
}

func newPubWriteProtocol(cfg *PubWriteProtocolConfig) (*pubWriteProtocol, error) {
	if cfg == nil {
		return nil, nil
	}
	if !filepath.IsAbs(cfg.StagingDirectory) || cfg.MaxArchiveBytes < 1 || cfg.MaxArchiveBytes > 64<<20 || cfg.MaxConcurrent < 1 || cfg.MaxConcurrent > 16 || cfg.Limits.MaxCompressedBytes != cfg.MaxArchiveBytes || cfg.Limits.MaxUncompressedBytes < 1 || cfg.Limits.MaxUncompressedBytes > 1<<30 || cfg.Limits.MaxEntries < 1 || cfg.Limits.MaxEntries > 100000 || cfg.Limits.MaxManifestBytes < 1 || cfg.Limits.MaxManifestBytes > 1<<20 {
		return nil, errors.New("Pub write protocol configuration is invalid")
	}
	info, err := os.Lstat(cfg.StagingDirectory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Pub write protocol staging directory must be private")
	}
	return &pubWriteProtocol{staging: cfg.StagingDirectory, maxArchive: cfg.MaxArchiveBytes, limits: cfg.Limits, slots: make(chan struct{}, cfg.MaxConcurrent)}, nil
}

// Native writes are experimental and require explicit opt-in.
func (h *authHTTP) registerPubWriteRoutes(router chi.Router) {
	base := "/pub/{workspaceID}/{repositoryID}"
	router.Get(base+"/api/packages/versions/new", h.pubStartUpload)
	router.Post(base+"/api/uploads/{uploadID}", h.pubUpload)
	router.Get(base+"/api/finalize/{uploadID}", h.pubFinalize)
}

func (h *authHTTP) pubStartUpload(response http.ResponseWriter, request *http.Request) {
	workspace, repository, ok := h.npmReadScope(response, request)
	if !ok {
		return
	}
	token, ok := h.pubWriteCredential(response, request, workspace, repository)
	if !ok {
		return
	}
	request, cancel, ok := goRequestContext(response, request, false)
	if !ok {
		return
	}
	defer cancel()
	id, err := h.pubReservations.StartNativeUpload(request.Context(), token, workspace, repository)
	if err != nil {
		writePubWriteError(response, err)
		return
	}
	base := h.canonicalOrigin + "/pub/" + workspace + "/" + repository
	npmReadJSON(response, http.StatusOK, map[string]any{"url": base + "/api/uploads/" + id, "fields": map[string]string{"upload_id": id}})
}

func (h *authHTTP) pubUpload(response http.ResponseWriter, request *http.Request) {
	workspace, repository, ok := h.npmReadScope(response, request)
	if !ok {
		return
	}
	token, ok := h.pubWriteCredential(response, request, workspace, repository)
	if !ok {
		return
	}
	id := chi.URLParam(request, "uploadID")
	if strings.Contains(strings.ToLower(request.URL.EscapedPath()), "%25") {
		pubProtocolError(response, http.StatusBadRequest, "INVALID_UPLOAD", "invalid upload")
		return
	}
	request, cancel, ok := goRequestContext(response, request, true)
	if !ok {
		return
	}
	defer cancel()
	if err := h.pubReservations.CheckNativeUpload(request.Context(), token, workspace, repository, id); err != nil {
		writePubWriteError(response, err)
		return
	}
	select {
	case h.pubWriteProtocol.slots <- struct{}{}:
		defer func() { <-h.pubWriteProtocol.slots }()
	default:
		pubProtocolError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "upload capacity unavailable")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, h.pubWriteProtocol.maxArchive+(1<<20))
	multipartReader, err := request.MultipartReader()
	if err != nil {
		pubProtocolError(response, http.StatusBadRequest, "INVALID_UPLOAD", "invalid multipart upload")
		return
	}
	stage, err := os.CreateTemp(h.pubWriteProtocol.staging, "pub-native-*")
	if err != nil {
		pubProtocolError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "upload staging unavailable")
		return
	}
	defer func() { _ = os.Remove(stage.Name()) }()
	defer stage.Close()
	size, err := readPubMultipart(request.Context(), multipartReader, stage, id, h.pubWriteProtocol.maxArchive)
	if err != nil {
		pubProtocolError(response, http.StatusBadRequest, "INVALID_UPLOAD", "invalid multipart upload")
		return
	}
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		pubProtocolError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "upload staging unavailable")
		return
	}
	digest := sha256.New()
	contents, err := pub.InspectArchive(request.Context(), io.TeeReader(stage, digest), h.pubWriteProtocol.limits)
	if err != nil {
		pubProtocolError(response, http.StatusBadRequest, "INVALID_PACKAGE", "invalid package archive")
		return
	}
	name, version, err := pub.ParsePubspecIdentity(contents.Manifest)
	if err != nil {
		pubProtocolError(response, http.StatusBadRequest, "INVALID_PACKAGE", "invalid package manifest")
		return
	}
	metadata := sha256.Sum256(contents.Manifest)
	reservation, err := h.pubReservations.ReserveNativeUpload(request.Context(), token, workspace, repository, id, pub.ReservationRequest{Name: name, Version: version, TarballSHA256: hex.EncodeToString(digest.Sum(nil)), TarballSize: size, MetadataSHA256: hex.EncodeToString(metadata[:])})
	if err != nil {
		writePubWriteError(response, err)
		return
	}
	received, err := h.pubReservations.NativeUploadReceived(request.Context(), token, workspace, repository, id, reservation.ID)
	if err != nil {
		writePubWriteError(response, err)
		return
	}
	if !received {
		if _, err := stage.Seek(0, io.SeekStart); err != nil {
			pubProtocolError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "upload staging unavailable")
			return
		}
		if err := h.pubReceipts.Receive(request.Context(), token, workspace, repository, reservation.ID, pub.ReceiptInput{Name: name, Version: version, Manifest: contents.Manifest, Size: size}, stage); err != nil {
			writePubWriteError(response, err)
			return
		}
	}
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("Location", h.canonicalOrigin+"/pub/"+workspace+"/"+repository+"/api/finalize/"+id)
	response.WriteHeader(http.StatusNoContent)
}

func (h *authHTTP) pubFinalize(response http.ResponseWriter, request *http.Request) {
	workspace, repository, ok := h.npmReadScope(response, request)
	if !ok {
		return
	}
	token, ok := h.pubWriteCredential(response, request, workspace, repository)
	if !ok {
		return
	}
	request, cancel, ok := goRequestContext(response, request, false)
	if !ok {
		return
	}
	defer cancel()
	_, err := h.pubReservations.PublishNativeUpload(request.Context(), token, workspace, repository, chi.URLParam(request, "uploadID"))
	if err != nil {
		writePubWriteError(response, err)
		return
	}
	npmReadJSON(response, http.StatusOK, map[string]any{"success": map[string]string{"message": "package published"}})
}

func writePubWriteError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repositories.ErrPubWriteTokenUnavailable):
		pubProtocolError(response, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "authentication required")
	case errors.Is(err, repositories.ErrReviewRequired):
		pubProtocolError(response, http.StatusConflict, "REVIEW_REQUIRED", "publication requires review")
	case errors.Is(err, pub.ErrReservationConflict), errors.Is(err, pub.ErrReservationQuota):
		pubProtocolError(response, http.StatusConflict, "UPLOAD_CONFLICT", "publication conflicts with registry state")
	case errors.Is(err, pub.ErrNativeUploadUnavailable), errors.Is(err, pub.ErrReservationUnavailable):
		pubProtocolError(response, http.StatusNotFound, "UPLOAD_NOT_FOUND", "upload unavailable")
	default:
		pubProtocolError(response, http.StatusServiceUnavailable, "UNAVAILABLE", "registry temporarily unavailable")
	}
}
