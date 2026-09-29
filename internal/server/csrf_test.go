package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
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

// loginTestHandler wires the real login handlers behind the CSRF middleware,
// mirroring buildRouter: POST /login is CSRF-checked, and GET /login is what
// hands the browser its token.
func loginTestHandler(t *testing.T) http.Handler {
	t.Helper()
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	s := newTestServer(t, tmpl)
	s.csrf = auth.NewCSRFManager([]byte("test-signing-key"))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLoginSubmit)
	return s.csrf.Middleware(mux)
}

var csrfFieldRe = regexp.MustCompile(`name="_csrf" value="([^"]*)"`)

// TestLoginPageCarriesCSRFCookieAndField is the regression test for a panel
// that answered every sign-in attempt with
//
//	CSRF check failed: csrf token missing
//
// login.html is a plain form, so the token cannot arrive through the layout's
// hx-headers: GET /login has to set the double-submit cookie *and* embed the
// very same value in a hidden field. Neither happened before renderLogin
// existed, which made POST /login unreachable for every user.
func TestLoginPageCarriesCSRFCookieAndField(t *testing.T) {
	h := loginTestHandler(t)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login: status = %d, want %d", rec.Code, http.StatusOK)
	}

	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "mailx_csrf" {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatalf("GET /login set no mailx_csrf cookie (%v): POST /login can only fail with 'csrf token missing'",
			rec.Result().Cookies())
	}

	m := csrfFieldRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("login.html has no hidden _csrf field; body:\n%s", rec.Body.String())
	}
	if m[1] != cookie.Value {
		t.Errorf("hidden _csrf value %q does not match cookie value %q", m[1], cookie.Value)
	}
}

// TestLoginPostWithIssuedTokenPassesCSRF proves the token minted by GET /login
// is accepted by POST /login. The empty credentials make the handler answer 400
// before it touches the database, which is enough to show the request got past
// the CSRF middleware instead of being rejected with 403.
func TestLoginPostWithIssuedTokenPassesCSRF(t *testing.T) {
	h := loginTestHandler(t)

	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/login", nil))

	m := csrfFieldRe.FindStringSubmatch(get.Body.String())
	if m == nil {
		t.Fatalf("GET /login rendered no _csrf field; body:\n%s", get.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range get.Result().Cookies() {
		if c.Name == "mailx_csrf" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("GET /login set no mailx_csrf cookie")
	}

	body := url.Values{"_csrf": {m[1]}, "username": {""}, "password": {""}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden || strings.Contains(rec.Body.String(), "CSRF check failed") {
		t.Fatalf("POST /login was rejected by CSRF: status = %d, body %q", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Username and password required") {
		t.Errorf("body %q does not show the credentials check ran", rec.Body.String())
	}
}

// TestLoginPostWithoutTokenIsStillRejected pins down the protection the fix
// must not weaken.
func TestLoginPostWithoutTokenIsStillRejected(t *testing.T) {
	h := loginTestHandler(t)

	body := url.Values{"username": {"admin"}, "password": {"x"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /login without a token: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

var formOpenTagRe = regexp.MustCompile(`(?i)<form\b[^>]*>`)

// TestPlainPostFormsCarryCSRFField is the static half of the same guard: a
// <form method="post"> without hx-* attributes does not inherit the layout's
// hx-headers, so it has to embed the token itself. login.html and the "Sign
// out" form in layout.html both shipped without it, which turns every such
// POST into "CSRF check failed: csrf token missing".
func TestPlainPostFormsCarryCSRFField(t *testing.T) {
	var forms int
	err := fs.WalkDir(assets, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".html") {
			return nil
		}
		src, err := fs.ReadFile(assets, p)
		if err != nil {
			return err
		}
		s := string(src)
		for _, loc := range formOpenTagRe.FindAllStringIndex(s, -1) {
			tag := strings.ToLower(s[loc[0]:loc[1]])
			if !strings.Contains(tag, `method="post"`) || strings.Contains(tag, "hx-") {
				continue // HTMX forms send the X-CSRF-Token header instead
			}
			forms++
			inner := s[loc[1]:]
			if end := strings.Index(inner, "</form>"); end >= 0 {
				inner = inner[:end]
			}
			if !strings.Contains(inner, `name="_csrf"`) {
				t.Errorf("%s: <form method=\"post\"> at offset %d has no hidden _csrf field", p, loc[0])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
	}
	if forms == 0 {
		t.Fatal("no plain POST forms found; the extractor regex is stale")
	}
}
