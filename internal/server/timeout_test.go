package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRequestTimeoutBudgets — every request that can block needs a deadline, and
// the routes that are long-lived by design must not get one. The v1.0.4 freeze
// started with a handler that had no budget at all.
func TestRequestTimeoutBudgets(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		want   time.Duration // 0 = no deadline imposed by the middleware
	}{
		{"page render", http.MethodGet, "/users", readTimeout},
		{"fragment", http.MethodGet, "/health/services", readTimeout},
		{"mutation", http.MethodPost, "/users", mutationTimeout},
		{"delete", http.MethodDelete, "/users/7", mutationTimeout},
		{"dns check", http.MethodGet, "/domains/3/dns/check", mutationTimeout},
		{"dashboard SSE", http.MethodGet, "/events", 0},
		{"log live tail", http.MethodGet, "/logs/live", 0},
		{"backup download", http.MethodGet, "/backup/download/20260101_000000.tar.gz", 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got time.Duration
			var hadDeadline bool

			h := testServer().requestTimeout(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				deadline, ok := r.Context().Deadline()
				hadDeadline = ok
				if ok {
					got = time.Until(deadline)
				}
			}))

			req := httptest.NewRequest(tc.method, tc.path, nil)
			h.ServeHTTP(httptest.NewRecorder(), req)

			if tc.want == 0 {
				if hadDeadline {
					t.Errorf("%s %s got a deadline of %s, want none", tc.method, tc.path, got)
				}
				return
			}
			if !hadDeadline {
				t.Fatalf("%s %s got no deadline, want %s", tc.method, tc.path, tc.want)
			}
			// Allow slack for the time the middleware itself took.
			if got > tc.want || got < tc.want-time.Second {
				t.Errorf("%s %s deadline in %s, want %s", tc.method, tc.path, got, tc.want)
			}
		})
	}
}

// TestRequestTimeoutKeepsTheParentContext — the budget has to be derived from
// the request's context, not from context.Background(), or cancelling the parent
// (server shutdown) would no longer stop in-flight work.
func TestRequestTimeoutKeepsTheParentContext(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())

	h := testServer().requestTimeout(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		cancelParent()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
			t.Error("cancelling the parent did not cancel the request context")
		}
	}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/users", nil).WithContext(parent))
}

// testServer is a Server carrying only what the timeout middleware touches: a
// logger for its report and the ring buffer /healthz reads.
func testServer() *Server {
	return &Server{
		logger:    slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{})),
		startedAt: time.Now(),
		timeouts:  newTimeoutLog(timeoutHistory),
	}
}

// TestRequestTimeoutAnswersAWedgedHandler is the regression test for the report
// this middleware exists for: "creating the user hangs and the page just keeps
// loading". A handler blocked on something that ignores its context never
// writes a response — without the middleware the connection stays open with no
// status, no error and no log line, and the operator has nothing to go on.
func TestRequestTimeoutAnswersAWedgedHandler(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) }) // let the stuck handler finish after the test

	srv := testServer()
	srv.budgetOverride = 50 * time.Millisecond

	h := srv.requestTimeout(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
			// The context *is* cancelled — the point is that this handler
			// ignores it and keeps waiting, like a blocked syscall would.
			<-release
		}
	}))

	rec := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/users", nil))
	elapsed := time.Since(start)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d: a wedged handler must be answered for", rec.Code, http.StatusServiceUnavailable)
	}
	if elapsed > 5*time.Second {
		t.Errorf("middleware returned after %s, want it bounded by the budget", elapsed)
	}
	if body := rec.Body.String(); !strings.Contains(body, "did not finish within") {
		t.Errorf("body does not explain the timeout:\n%s", body)
	}

	recent := srv.timeouts.recent()
	if len(recent) != 1 {
		t.Fatalf("recorded %d timeouts, want 1", len(recent))
	}
	if recent[0].Method != http.MethodPost || recent[0].Path != "/users" {
		t.Errorf("recorded %s %s, want POST /users", recent[0].Method, recent[0].Path)
	}
	// The dump is the whole point: it has to contain a stack.
	if !strings.Contains(recent[0].Stack, "goroutine ") {
		t.Errorf("no goroutine dump captured:\n%s", recent[0].Stack)
	}
}

// TestRequestTimeoutAnswersHTMXWithAFragment — a fragment request must not get a
// full page swapped into a table, and it must carry the status the client-side
// handler in static/app.js turns into a toast.
func TestRequestTimeoutAnswersHTMXWithAFragment(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	srv := testServer()
	srv.budgetOverride = 50 * time.Millisecond

	h := srv.requestTimeout(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))

	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "alert alert-error") || strings.Contains(body, "<html") {
		t.Errorf("HTMX body is not a bare fragment:\n%s", body)
	}
}

// TestRequestTimeoutDeliversAFastResponseUnchanged — the middleware buffers, so
// it has to hand a normal response through untouched: status, headers (HTMX
// redirects depend on them) and body.
func TestRequestTimeoutDeliversAFastResponseUnchanged(t *testing.T) {
	srv := testServer()
	srv.budgetOverride = 30 * time.Second // the handler never needs it

	h := srv.requestTimeout(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("HX-Redirect", "/users?flash=ok")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created\n"))
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/users", nil))

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if got := rec.Header().Get("HX-Redirect"); got != "/users?flash=ok" {
		t.Errorf("HX-Redirect = %q, want it passed through", got)
	}
	if rec.Body.String() != "created\n" {
		t.Errorf("body = %q, want it passed through", rec.Body.String())
	}
	if len(srv.timeouts.recent()) != 0 {
		t.Error("a request that finished inside its budget was recorded as a timeout")
	}
}

// TestRequestTimeoutLeavesStreamsAlone — /events and the log tail are long-lived
// on purpose: no budget, and no buffering either, or their output would never
// reach the browser.
func TestRequestTimeoutLeavesStreamsAlone(t *testing.T) {
	srv := testServer()
	srv.budgetOverride = time.Nanosecond

	h := srv.requestTimeout(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("data: ping\n\n"))
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/events", nil))

	if rec.Body.String() != "data: ping\n\n" {
		t.Errorf("stream body = %q, want it written straight through", rec.Body.String())
	}
}

// TestRequestTimeoutRecoversAPanic — the handler runs in a goroutine the
// middleware owns, so a panic would crash the whole panel unless it is caught.
func TestRequestTimeoutRecoversAPanic(t *testing.T) {
	srv := testServer()
	srv.budgetOverride = 30 * time.Second

	h := srv.requestTimeout(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// TestTimeoutLogKeepsNewestFirst — /healthz/stacks lists these, so the most
// recent timeout has to come first.
func TestTimeoutLogKeepsNewestFirst(t *testing.T) {
	log := newTimeoutLog(3)
	for _, path := range []string{"/one", "/two", "/three", "/four"} {
		log.add(timeoutRecord{Path: path, At: time.Now()})
	}

	got := log.recent()
	if len(got) != 3 {
		t.Fatalf("kept %d records, want the ring size 3", len(got))
	}
	for i, want := range []string{"/four", "/three", "/two"} {
		if got[i].Path != want {
			t.Errorf("record %d = %s, want %s", i, got[i].Path, want)
		}
	}
}
