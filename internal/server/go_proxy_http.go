package server

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/mod/module"
	"private-registry/internal/gomod"
	"private-registry/internal/repositories"
)

// Missing private names, including ancestors of configured private prefixes,
// return terminal 403. Confirmed public names may return 404 for a
// comma-separated GOPROXY chain; invalid requests fail closed.
func (h *authHTTP) goModuleProxy(response http.ResponseWriter, request *http.Request) {
	requestOrigin, err := normalizeOrigin("https://" + request.Host)
	if err != nil || requestOrigin != h.canonicalOrigin || !requestUsesHTTPS(request, h.trustedProxies) {
		writeAPIError(response, http.StatusForbidden, "origin_rejected")
		return
	}
	actorID, ok := h.authenticatePersonalToken(response, request)
	if !ok {
		return
	}
	response.Header().Set("Cache-Control", "private, no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Vary", "Authorization")
	path := chi.URLParam(request, "*")
	escapedPath, operation, version, valid := parseGoProxyPath(path)
	if !valid || request.URL.RawQuery != "" {
		writeAPIError(response, http.StatusForbidden, "private_module_unavailable")
		return
	}
	modulePath, err := module.UnescapePath(escapedPath)
	if err != nil || module.CheckPath(modulePath) != nil {
		writeAPIError(response, http.StatusForbidden, "private_module_unavailable")
		return
	}
	workspaceID, repositoryID := chi.URLParam(request, "workspaceID"), chi.URLParam(request, "repositoryID")
	var body []byte
	var contentType string
	switch operation {
	case "list":
		versions, err := h.goModules.ListVersions(request.Context(), actorID, workspaceID, repositoryID, modulePath)
		if err != nil {
			h.writeGoProxyError(response, request, actorID, workspaceID, repositoryID, modulePath, err)
			return
		}
		if len(versions) > 0 {
			body = []byte(strings.Join(versions, "\n") + "\n")
		}
		contentType = "text/plain; charset=utf-8"
	case "latest":
		info, err := h.goModules.Latest(request.Context(), actorID, workspaceID, repositoryID, modulePath)
		if err != nil {
			h.writeGoProxyError(response, request, actorID, workspaceID, repositoryID, modulePath, err)
			return
		}
		body, err = gomod.MarshalVersionInfo(modulePath, info)
		if err != nil {
			h.writeGoProxyError(response, request, actorID, workspaceID, repositoryID, modulePath, err)
			return
		}
		contentType = "application/json"
	case "info", "mod":
		resolved, err := h.goModules.GetVersion(request.Context(), actorID, workspaceID, repositoryID, modulePath, version)
		if err != nil {
			h.writeGoProxyError(response, request, actorID, workspaceID, repositoryID, modulePath, err)
			return
		}
		if operation == "info" {
			body, err = gomod.MarshalVersionInfo(modulePath, resolved.Info)
			if err != nil {
				h.writeGoProxyError(response, request, actorID, workspaceID, repositoryID, modulePath, err)
				return
			}
			contentType = "application/json"
		} else {
			body = resolved.Mod
			contentType = "text/plain; charset=utf-8"
		}
	case "zip":
		reader, size, err := h.goModules.OpenZip(request.Context(), actorID, workspaceID, repositoryID, modulePath, version)
		if err != nil {
			h.writeGoProxyError(response, request, actorID, workspaceID, repositoryID, modulePath, err)
			return
		}
		defer reader.Close()
		response.Header().Set("Content-Type", "application/zip")
		response.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		response.WriteHeader(http.StatusOK)
		if request.Method != http.MethodHead {
			_, _ = io.CopyN(response, reader, size)
		}
		return
	default:
		writeAPIError(response, http.StatusForbidden, "private_module_unavailable")
		return
	}
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	response.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = response.Write(body)
	}
}

func parseGoProxyPath(path string) (escapedModule, operation, version string, valid bool) {
	if len(path) == 0 || len(path) > 2048 || strings.HasPrefix(path, "/") {
		return "", "", "", false
	}
	if strings.HasSuffix(path, "/@latest") {
		escapedModule = strings.TrimSuffix(path, "/@latest")
		operation = "latest"
	} else {
		index := strings.LastIndex(path, "/@v/")
		if index < 1 {
			return "", "", "", false
		}
		escapedModule = path[:index]
		file := path[index+len("/@v/"):]
		if file == "list" {
			operation = "list"
		} else {
			for _, suffix := range []string{"info", "mod", "zip"} {
				if strings.HasSuffix(file, "."+suffix) {
					operation = suffix
					version = strings.TrimSuffix(file, "."+suffix)
					break
				}
			}
			unescaped, err := module.UnescapeVersion(version)
			if err != nil || unescaped == "" {
				return "", "", "", false
			}
			reescaped, err := module.EscapeVersion(unescaped)
			if err != nil || reescaped != version {
				return "", "", "", false
			}
			version = unescaped
		}
	}
	unescaped, err := module.UnescapePath(escapedModule)
	if err != nil || unescaped == "" {
		return "", "", "", false
	}
	reescaped, err := module.EscapePath(unescaped)
	if err != nil || reescaped != escapedModule {
		return "", "", "", false
	}
	return escapedModule, operation, version, operation != ""
}

func (h *authHTTP) writeGoProxyError(response http.ResponseWriter, request *http.Request, actorID, workspaceID, repositoryID, modulePath string, err error) {
	if errors.Is(err, gomod.ErrModuleUnavailable) {
		private, policyErr := h.repositories.IsGoPrivateNamespace(request.Context(), actorID, workspaceID, repositoryID, modulePath)
		if policyErr != nil {
			writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
		if !private {
			writeAPIError(response, http.StatusNotFound, "module_not_found")
			return
		}
	}
	if errors.Is(err, gomod.ErrModuleUnavailable) || errors.Is(err, repositories.ErrForbidden) || errors.Is(err, repositories.ErrFormatMismatch) || errors.Is(err, repositories.ErrRepositoryUnavailable) {
		writeAPIError(response, http.StatusForbidden, "private_module_unavailable")
		return
	}
	writeAPIError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
}
