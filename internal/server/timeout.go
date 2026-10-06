package server

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"net/http"
	"runtime"
	"strings"
	"sync"
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

	// updateApplyBudget bounds the self-update download+install. The download
	// runs on its own context (see handlers_updates.go); this only widens the
	// response budget so the browser is not answered with a timeout first.
	updateApplyBudget = 3 * time.Minute

	// timeoutGrace is how long a handler that finished at the very moment the
	// budget ran out still gets to flush its answer. Without it a create that
	// completed at 30.0s would be reported as a timeout, and the operator would
	// retry an action that actually succeeded.
	timeoutGrace = 250 * time.Millisecond

	// timeoutHistory is how many timed-out requests are kept for /healthz.
	timeoutHistory = 8

	// stackDumpLimit bounds the goroutine dump taken on a timeout. A dump big
	// enough to be truncated means "hundreds of goroutines", which is itself
	// the answer; growing the buffer would only make the timeout worse.
	stackDumpLimit = 1 << 20
)

// streamingPaths never get a request budget: they are long-lived by design.
var streamingPaths = map[string]bool{
	"/events":      true, // dashboard SSE
	"/logs/live":   true, // log live tail SSE
	"/terminal/ws": true, // interactive shell WebSocket
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

// defaultBudget returns the request budget for a route by shape and method.
func defaultBudget(r *http.Request) time.Duration {
	switch {
	case r.URL.Path == "/system/updates/apply":
		return updateApplyBudget
	case r.Method != http.MethodGet && r.Method != http.MethodHead:
		return mutationTimeout
	case isSlowRead(r.URL.Path):
		return mutationTimeout
	default:
		return readTimeout
	}
}

// budgetFor is defaultBudget with a test seam: budgetOverride lets the timeout
// tests drive the real middleware without waiting fifteen seconds for it.
func (s *Server) budgetFor(r *http.Request) time.Duration {
	if s.budgetOverride > 0 {
		return s.budgetOverride
	}
	return defaultBudget(r)
}

// requestTimeout gives every request a budget *and* an answer.
//
// The deadline alone was not enough, and the difference is what the operator
// sees. A handler that blocks on something that honours its context — a pooled
// connection, postmap, systemctl, a DNS lookup — gives up when the deadline
// passes and reports an error. A handler that blocks on something that ignores
// it — a statement the driver cannot interrupt, a helper stuck on a lock, an
// exec started without a timeout — never returns at all, and then *no* response
// is ever written: no status, no error, nothing. The browser shows a spinner
// until the tab is closed and the journal shows silence. That is the "the panel
// just loads forever" report, and it is why the handler now runs in a goroutine
// the middleware owns: when the budget is gone the middleware answers for it.
//
// The dump taken at that moment is the point of the exercise: it names the frame
// the request is stuck in, which is the difference between guessing and fixing.
// It goes to the log and to /healthz/stacks.
func (s *Server) requestTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isStreamingPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		budget := s.budgetFor(r)
		ctx, cancel := context.WithTimeout(r.Context(), budget)
		defer cancel()

		buf := newBufferedResponse()
		done := make(chan struct{})

		go func() {
			defer close(done)
			defer func() {
				if rec := recover(); rec != nil {
					// net/http recovers panics in its own goroutine; this one
					// is ours, so an unrecovered panic would take the panel
					// down instead of failing one request.
					s.logPanic(r, rec)
					buf.fail(http.StatusInternalServerError, "text/plain; charset=utf-8",
						"Internal server error. See `journalctl -u mailx-admin`.\n")
				}
			}()
			next.ServeHTTP(buf, r.WithContext(ctx))
		}()

		select {
		case <-done:
			buf.flush(w)
		case <-ctx.Done():
			// The client hung up, or the server is shutting down: there is
			// nobody left to answer.
			if r.Context().Err() != nil {
				buf.drop()
				return
			}

			// A handler that finished at the same moment the budget ran out
			// still wins. Answering "timed out" for a create that committed
			// would make the operator retry an action that already happened.
			select {
			case <-done:
				buf.flush(w)
				return
			case <-time.After(timeoutGrace):
			}

			rec := s.noteTimeout(r, budget)
			buf.reset()
			buf.Header().Set("Content-Type", "text/html; charset=utf-8")
			buf.WriteHeader(http.StatusServiceUnavailable)
			if r.Header.Get("HX-Request") == "true" {
				fmt.Fprint(buf, timeoutFragment(rec))
			} else {
				fmt.Fprint(buf, timeoutPage(rec))
			}
			buf.flush(w)
		}
	})
}

// logPanic reports a handler panic with the stack it happened on.
func (s *Server) logPanic(r *http.Request, rec any) {
	if s.logger == nil {
		return
	}
	s.logger.Error("panic in handler",
		"method", r.Method, "path", r.URL.Path, "panic", rec, "stack", shortStack())
}

// noteTimeout logs a request that ran out of budget, remembers it for /healthz,
// and returns the record the response is built from.
func (s *Server) noteTimeout(r *http.Request, budget time.Duration) timeoutRecord {
	record := timeoutRecord{
		At:     time.Now(),
		Method: r.Method,
		Path:   r.URL.Path,
		Budget: budget,
		Stack:  goroutineDump(),
	}
	if s.logger != nil {
		s.logger.Error("request timed out; the handler is still running",
			"method", record.Method, "path", record.Path,
			"budget", budget.String(), "remote", r.RemoteAddr)
		// A second record, so the dump stays readable instead of becoming one
		// quoted field of several kilobytes.
		s.logger.Error("goroutines at timeout:\n" + record.Stack)
	}
	if s.timeouts != nil {
		s.timeouts.add(record)
	}
	return record
}

// timeoutRecord is one request that ran out of budget. Stack holds every
// goroutine's stack at that moment: the evidence of what it was waiting for.
type timeoutRecord struct {
	At     time.Time
	Method string
	Path   string
	Budget time.Duration
	Stack  string
}

// Summary is the one-line form the log and /healthz show.
func (r timeoutRecord) Summary() string {
	return fmt.Sprintf("%s %s timed out after %s", r.Method, r.Path, r.Budget)
}

// timeoutFragment is the body an HTMX request gets. HTMX does not swap 5xx
// bodies by default, so static/app.js turns the status into a toast; the
// fragment covers the requests that do swap it.
func timeoutFragment(rec timeoutRecord) string {
	return fmt.Sprintf(`<div class="alert alert-error" role="alert">
  <strong>The request took too long.</strong>
  <p>%s did not finish within %s. Nothing was lost — the work continues on the server and its
  result shows up on the dashboard. If it keeps happening, open <a href="/healthz/stacks">the
  diagnostic page</a> or run <code>journalctl -u mailx-admin</code> to see what it waited for.</p>
</div>`, html.EscapeString(rec.Method+" "+rec.Path), html.EscapeString(rec.Budget.String()))
}

// timeoutPage answers a full page load that ran out of budget.
//
// It is written by hand rather than rendered from the panel's templates, and
// that is deliberate: the timeout path must not depend on anything else —
// not the template set, not the database, not a session — or a broken
// dependency would turn "this page is slow" into "the browser got a panic and
// no page at all".
func timeoutPage(rec timeoutRecord) string {
	when := rec.At.Format("2006-01-02 15:04:05")
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Request timed out</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
         margin: 0; padding: 3rem 1.25rem; background: #0f1115; color: #e6e8eb; }
  main { max-width: 46rem; margin: 0 auto; }
  h1 { font-size: 1.3rem; margin: 0 0 .75rem; }
  code { font-family: ui-monospace, Menlo, Consolas, monospace; }
  a { color: #7cb7ff; }
  .meta { color: #9aa4b2; font-size: .9rem; }
</style>
</head>
<body>
<main>
  <h1>The request took too long</h1>
  <p>%s did not finish within <strong>%s</strong>, so the panel stopped waiting. The work may
  still be running on the server — reload this page in a moment before repeating the action.</p>
  <p class="meta">What it was waiting for is in the <a href="/healthz/stacks">goroutine dump</a>
  (after signing in) and in <code>journalctl -u mailx-admin</code>.</p>
  <p class="meta">Request <code>%s %s</code> &middot; %s</p>
  <p><a href="/">Back to the dashboard</a></p>
</main>
</body>
</html>`,
		html.EscapeString(rec.Method+" "+rec.Path),
		html.EscapeString(rec.Budget.String()),
		html.EscapeString(rec.Method),
		html.EscapeString(rec.Path),
		html.EscapeString(when),
	)
}

// timeoutLog remembers the most recent timeouts so an operator can see them
// without a shell. Fixed size: it must never grow.
type timeoutLog struct {
	mu   sync.Mutex
	recs []timeoutRecord
	next int
	n    int
}

func newTimeoutLog(size int) *timeoutLog {
	if size <= 0 {
		size = timeoutHistory
	}
	return &timeoutLog{recs: make([]timeoutRecord, size)}
}

func (l *timeoutLog) add(rec timeoutRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.recs[l.next] = rec
	l.next = (l.next + 1) % len(l.recs)
	if l.n < len(l.recs) {
		l.n++
	}
}

// recent returns the recorded timeouts, newest first.
func (l *timeoutLog) recent() []timeoutRecord {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make([]timeoutRecord, 0, l.n)
	for i := 0; i < l.n; i++ {
		idx := (l.next - 1 - i + len(l.recs)) % len(l.recs)
		out = append(out, l.recs[idx])
	}
	return out
}

// goroutineDump renders every goroutine's stack.
func goroutineDump() string {
	buf := make([]byte, stackDumpLimit)
	n := runtime.Stack(buf, true)
	if n >= len(buf) {
		return string(buf) + "\n... (dump truncated)"
	}
	return string(buf[:n])
}

// shortStack is the current goroutine only, for panic reports.
func shortStack() string {
	buf := make([]byte, 8<<10)
	return string(buf[:runtime.Stack(buf, false)])
}

// bufferedResponse collects a handler's response instead of sending it, so the
// middleware can still replace it with a timeout page once the budget is gone.
//
// It has the same shape as net/http's own TimeoutHandler: Header returns the
// live map, Write and WriteHeader take the lock, and the middleware freezes the
// buffer exactly once. After that every write is swallowed — and swallowing,
// rather than returning an error, is deliberate: the timed-out handler is still
// running, and a template that suddenly got a write error would log a second,
// misleading failure for a request that has already been answered.
type bufferedResponse struct {
	mu     sync.Mutex
	header http.Header
	status int
	body   bytes.Buffer
	frozen bool
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header)}
}

func (b *bufferedResponse) Header() http.Header {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.header
}

func (b *bufferedResponse) WriteHeader(status int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.frozen || b.status != 0 {
		return
	}
	b.status = status
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.frozen {
		return len(p), nil
	}
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

// reset throws away whatever the handler produced so far, for the case where
// the middleware is about to answer instead. It replaces the header map rather
// than clearing it, so a header a stuck handler sets later lands in a map that
// nobody reads.
func (b *bufferedResponse) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.frozen {
		return
	}
	b.header = make(http.Header)
	b.status = 0
	b.body.Reset()
}

// fail replaces the response with a complete error, headers included. It is the
// panic path, and it has to be a single call: it runs in the handler's
// goroutine and may race with the middleware answering the client.
func (b *bufferedResponse) fail(status int, contentType, body string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.frozen {
		return
	}
	b.header = make(http.Header)
	b.header.Set("Content-Type", contentType)
	b.header.Set("Cache-Control", "no-store")
	b.status = status
	b.body.Reset()
	b.body.WriteString(body)
}

// drop freezes the buffer without sending anything (the client is gone).
func (b *bufferedResponse) drop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.frozen = true
}

// flush sends the buffered response and freezes the buffer, so nothing the
// handler does afterwards can touch the connection again.
func (b *bufferedResponse) flush(w http.ResponseWriter) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.frozen {
		return
	}
	b.frozen = true

	if b.status == 0 {
		b.status = http.StatusOK
	}
	dst := w.Header()
	for k, vv := range b.header {
		dst[k] = append([]string(nil), vv...)
	}
	w.WriteHeader(b.status)
	if b.body.Len() > 0 {
		_, _ = w.Write(b.body.Bytes())
	}
}
