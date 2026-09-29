package server

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Request budgets.
//
// These are the panel's last line of defence behind the client-side htmx
// timeout (static/app.js) and Apache's 60s upstream timeout. A handler that
// ignores its context would still block until the client gives up — but every
// handler that can block now goes through something that honours the context:
// database/sql (internal/db, internal/store), execx (postmap, systemctl,
// postqueue, certbot) and the DNS checker.
const (
	// readTimeout bounds a normal page or fragment render.
	readTimeout = 15 * time.Second

	// mutationTimeout bounds a write. A mutation renders the full config set,
	// runs postmap and may reload a service, so it gets twice the budget.
	mutationTimeout = 30 * time.Second
)

// streamingPaths never get a request budget: they are long-lived by design.
var streamingPaths = map[string]bool{
	"/events":    true, // dashboard SSE
	"/logs/live": true, // log live tail SSE
}

// isStreamingPath reports whether the path is a long-lived stream or download
// that must not be cut off by a request budget.
func isStreamingPath(path string) bool {
	if streamingPaths[path] {
		return true
	}
	// Backup downloads stream a tarball that can be gigabytes; Apache's own
	// timeout is the right limit there.
	return strings.HasPrefix(path, "/backup/download/")
}

// isSlowRead reports GET routes that legitimately need longer than readTimeout:
// the DNS check performs live lookups against the public resolvers for every
// record of a domain.
func isSlowRead(path string) bool {
	return strings.HasSuffix(path, "/dns/check")
}

// requestTimeout gives every request a deadline, so a wedged dependency ends as
// a failed request with a message instead of a hung connection. Without it the
// first stuck handler keeps its HTTP worker (and, for writes, its SQLite
// connection) until the browser or Apache gives up.
func requestTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isStreamingPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		budget := readTimeout
		switch {
		case r.Method != http.MethodGet && r.Method != http.MethodHead:
			budget = mutationTimeout
		case isSlowRead(r.URL.Path):
			budget = mutationTimeout
		}

		ctx, cancel := context.WithTimeout(r.Context(), budget)
		defer cancel()

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
