package npm

import (
	"errors"
	"strings"
)

// ValidatePackageName accepts a conservative ASCII subset of names permitted
// for new npm packages. It does not prove compatibility with all npm clients,
// reserve a name, resolve routing or authorize an actor.
func ValidatePackageName(name string) error {
	if len(name) < 1 || len(name) > 214 {
		return errors.New("npm package name is invalid")
	}
	if strings.HasPrefix(name, "@") {
		scope, packageName, found := strings.Cut(name[1:], "/")
		if !found || scope == "" || packageName == "" || strings.Contains(packageName, "/") || strings.HasPrefix(packageName, ".") || !safeNamePart(scope) || !safeNamePart(packageName) {
			return errors.New("npm scoped package name is invalid")
		}
		return nil
	}
	if strings.Contains(name, "/") || strings.ContainsAny(name[:1], "._-") || !safeNamePart(name) || name == "node_modules" || name == "favicon.ico" {
		return errors.New("npm package name is invalid")
	}
	if _, found := nodeCoreNames[name]; found {
		return errors.New("npm package name is reserved")
	}
	return nil
}

func safeNamePart(value string) bool {
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

// Node.js 24 builtins relevant to unscoped names; slash-containing and
// underscore-prefixed builtins are already rejected by the checks above.
var nodeCoreNames = map[string]struct{}{
	"assert": {}, "async_hooks": {}, "buffer": {}, "child_process": {},
	"cluster": {}, "console": {}, "constants": {}, "crypto": {}, "dgram": {},
	"diagnostics_channel": {}, "dns": {}, "domain": {}, "events": {}, "fs": {},
	"http": {}, "http2": {}, "https": {}, "inspector": {}, "module": {},
	"net": {}, "os": {}, "path": {}, "perf_hooks": {}, "process": {},
	"punycode": {}, "querystring": {}, "readline": {}, "repl": {}, "stream": {},
	"string_decoder": {}, "sys": {}, "timers": {}, "tls": {}, "trace_events": {},
	"tty": {}, "url": {}, "util": {}, "v8": {}, "vm": {}, "wasi": {},
	"worker_threads": {}, "zlib": {},
}
