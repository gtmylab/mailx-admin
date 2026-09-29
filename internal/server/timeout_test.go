package server

import (
	"context"
	"net/http"
	"net/http/httptest"
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

			h := requestTimeout(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
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

	h := requestTimeout(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		cancelParent()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
			t.Error("cancelling the parent did not cancel the request context")
		}
	}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/users", nil).WithContext(parent))
}
