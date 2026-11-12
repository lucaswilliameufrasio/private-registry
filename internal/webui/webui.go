// Package webui serves the browser interface: static files embedded in the
// binary, with no build step and no third-party code. The interface talks to
// the same HTTP API as every other client, on the canonical origin, so the
// session cookie, CSRF token and origin checks apply unchanged.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
)

//go:embed static
var files embed.FS

// contentSecurityPolicy allows only this origin's own scripts, styles and API
// calls: no inline code, no frames, no forms to other origins.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// Handler serves "/" and "/ui/*". allowed decides whether a request reached
// the canonical origin; requests elsewhere, such as the asset origin, get 404.
func Handler(allowed func(*http.Request) bool) http.Handler {
	static, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	contentTypes := map[string]string{".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !allowed(request) {
			http.NotFound(response, request)
			return
		}
		name := "index.html"
		if request.URL.Path != "/" {
			name = path.Base(request.URL.Path)
			if request.URL.Path != "/ui/"+name || (name != "app.js" && name != "app.css") {
				http.NotFound(response, request)
				return
			}
		}
		content, err := fs.ReadFile(static, name)
		if err != nil {
			http.NotFound(response, request)
			return
		}
		header := response.Header()
		header.Set("Content-Type", contentTypes[path.Ext(name)])
		header.Set("Content-Security-Policy", contentSecurityPolicy)
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("Cross-Origin-Opener-Policy", "same-origin")
		header.Set("Cache-Control", "no-cache")
		response.WriteHeader(http.StatusOK)
		if request.Method == http.MethodGet {
			_, _ = response.Write(content)
		}
	})
}
