package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/auth"
)

// csrfTestHandler wires the real CSRF middleware in front of a handler that
// always responds 200 "ok", and returns the manager used to mint tokens.
func csrfTestHandler() (*auth.CSRFManager, http.Handler) {
	m := auth.NewCSRFManager([]byte("test-signing-key"))
	return m, m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
}

// issueToken mints a token and returns the cookie the browser would store.
func issueToken(t *testing.T, m *auth.CSRFManager) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if _, err := m.Issue(rec); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Issue set %d cookies, want 1", len(cookies))
	}
	return cookies[0]
}

func TestCSRFMiddleware_RejectsMissingToken(t *testing.T) {
	_, h := csrfTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/domains", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without token: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), "csrf") {
		t.Errorf("body %q does not mention csrf", rec.Body.String())
	}
}

func TestCSRFMiddleware_AcceptsMatchingToken(t *testing.T) {
	m, h := csrfTestHandler()
	cookie := issueToken(t, m)

	t.Run("header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/domains", nil)
		req.AddCookie(cookie)
		req.Header.Set("X-CSRF-Token", cookie.Value)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}
	})

	t.Run("form field", func(t *testing.T) {
		body := url.Values{"_csrf": {cookie.Value}, "name": {"example.com"}}
		req := httptest.NewRequest(http.MethodPost, "/domains", strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
		}
	})
}

func TestCSRFMiddleware_RejectsMismatchedToken(t *testing.T) {
	_, h := csrfTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/domains", nil)
	req.AddCookie(&http.Cookie{Name: "mailx_csrf", Value: "cookie-value"})
	req.Header.Set("X-CSRF-Token", "different-value")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestCSRFMiddleware_SafeMethodsPass(t *testing.T) {
	_, h := csrfTestHandler()

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(method, "/dashboard", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s without token: status = %d, want %d", method, rec.Code, http.StatusOK)
		}
	}
}
