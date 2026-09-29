package server

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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

// --- regression tests for the rotating CSRF token --------------------------
//
// The panel used to answer "CSRF check failed: csrf token invalid" on every
// write from some pages and at random on the others. Two independent defects:
//
//	1. every render minted a new token and overwrote the one mailx_csrf cookie
//	   the browser keeps, so the token still embedded in the page the user was
//	   looking at (another tab, a reload, a bfcache restore) was stale the
//	   moment any other page was fetched;
//	2. Verify let a present-but-empty/stale X-CSRF-Token header shadow a valid
//	   _csrf form field - and six handlers rendered their page with an empty
//	   token in the first place, because they built pageData by hand instead of
//	   calling newPageData.
//
// The tests below fail on the pre-fix code.

// getLoginPage performs GET /login the way a browser would, with whatever
// mailx_csrf cookie it already holds, and returns the _csrf value from the
// rendered form plus the cookie that response set (nil when it set none, i.e.
// the browser keeps the one it had).
func getLoginPage(t *testing.T, h http.Handler, held *http.Cookie) (string, *http.Cookie) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	if held != nil {
		req.AddCookie(held)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login: status = %d, want %d", rec.Code, http.StatusOK)
	}
	m := csrfFieldRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("GET /login rendered no _csrf field; body:\n%s", rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "mailx_csrf" {
			return m[1], c
		}
	}
	return m[1], nil
}

// TestLoginTokenIsStableAcrossRenders drives two page loads like a browser and
// then submits the *first* page's form with the cookie the browser ends up
// holding - the exact sequence that answered "csrf token invalid" before, in
// the form of a second tab or a password manager re-fetching /login.
func TestLoginTokenIsStableAcrossRenders(t *testing.T) {
	h := loginTestHandler(t)

	field1, cookie1 := getLoginPage(t, h, nil)
	if cookie1 == nil || cookie1.Value == "" {
		t.Fatal("first GET /login set no mailx_csrf cookie")
	}

	field2, cookie2 := getLoginPage(t, h, cookie1)

	// The browser stores at most one mailx_csrf cookie: whatever the second
	// response did to it is what every later request carries.
	held := cookie1
	if cookie2 != nil {
		held = cookie2
	}

	if field2 != field1 {
		t.Errorf("two renders of /login produced different tokens:\n first: %q\nsecond: %q\n"+
			"a rotating token invalidates every page that is already open", field1, field2)
	}
	if held.Value != cookie1.Value {
		t.Errorf("second GET /login rotated the cookie: %q -> %q", cookie1.Value, held.Value)
	}
	if field1 != held.Value {
		t.Errorf("rendered token %q does not match the cookie the browser holds %q", field1, held.Value)
	}

	body := url.Values{"_csrf": {field1}, "username": {""}, "password": {""}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(held)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("submitting the first render's form with the browser's current cookie was rejected: status = %d, body %q",
			rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestEnsureReusesTheCookieInsteadOfRotatingIt pins the manager-level contract:
// a request that already carries one of our tokens gets it back, unchanged, and
// the response does not touch the cookie.
func TestEnsureReusesTheCookieInsteadOfRotatingIt(t *testing.T) {
	m := auth.NewCSRFManager([]byte("test-signing-key"))
	held := issueToken(t, m)

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	req.AddCookie(held)
	rec := httptest.NewRecorder()

	got, err := m.Ensure(rec, req)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if got != held.Value {
		t.Errorf("Ensure returned %q, want the token the browser already has %q", got, held.Value)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("Ensure re-set the cookie (%v); every re-set token invalidates the other open pages", cookies)
	}

	t.Run("forged cookie is replaced", func(t *testing.T) {
		forged := &http.Cookie{Name: "mailx_csrf", Value: "not-ours"}
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		req.AddCookie(forged)
		rec := httptest.NewRecorder()

		got, err := m.Ensure(rec, req)
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if got == forged.Value {
			t.Error("Ensure accepted a token this manager never signed")
		}
		if cookies := rec.Result().Cookies(); len(cookies) != 1 || cookies[0].Value != got {
			t.Errorf("Ensure did not set a matching cookie: %v (token %q)", rec.Result().Cookies(), got)
		}
	})

	t.Run("no cookie yet mints one", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		rec := httptest.NewRecorder()

		got, err := m.Ensure(rec, req)
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if got == "" {
			t.Error("Ensure returned an empty token for a request without a cookie")
		}
		if cookies := rec.Result().Cookies(); len(cookies) != 1 || cookies[0].Value != got {
			t.Errorf("Ensure did not set a matching cookie: %v (token %q)", rec.Result().Cookies(), got)
		}
	})
}

// TestVerifyAcceptsTheFormFieldEvenWhenTheHeaderIsUnusable covers defect 2:
// hx-headers shipped an empty (or stale) X-CSRF-Token, and the header used to
// win whenever it was present, so a perfectly valid _csrf form field was
// ignored and the request answered "csrf token invalid".
func TestVerifyAcceptsTheFormFieldEvenWhenTheHeaderIsUnusable(t *testing.T) {
	m, h := csrfTestHandler()
	cookie := issueToken(t, m)

	for _, header := range []string{"", "stale-token-from-an-earlier-render"} {
		name := "empty header"
		if header != "" {
			name = "stale header"
		}
		t.Run(name, func(t *testing.T) {
			body := url.Values{"_csrf": {cookie.Value}, "name": {"example.com"}}
			req := httptest.NewRequest(http.MethodPost, "/domains", strings.NewReader(body.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-CSRF-Token", header)
			req.AddCookie(cookie)

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("valid _csrf field with %s: status = %d, want %d (body %q)",
					name, rec.Code, http.StatusOK, rec.Body.String())
			}
		})
	}

	// And the guard the fix must not weaken: a forged pair is still rejected.
	t.Run("forged pair is rejected", func(t *testing.T) {
		body := url.Values{"_csrf": {"forged"}, "name": {"example.com"}}
		req := httptest.NewRequest(http.MethodPost, "/domains", strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", "forged")
		req.AddCookie(&http.Cookie{Name: "mailx_csrf", Value: "forged"})

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})
}

// TestFullPageRenderCarriesTheCookieToken drives newPageData + layout.html end
// to end and checks every place the token has to appear: the cookie, the
// hx-headers on <body> (every HTMX write reads it) and the "Sign out" form.
func TestFullPageRenderCarriesTheCookieToken(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	s := newTestServer(t, tmpl)
	s.csrf = auth.NewCSRFManager([]byte("test-signing-key"))

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	rec := httptest.NewRecorder()

	data := s.newPageData(rec, req, "Users", "users", map[string]any{"Users": nil, "Total": 0, "Query": ""})
	if data.CSRFToken == "" {
		t.Fatal("newPageData produced an empty CSRF token: every write from this page would 403")
	}

	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "mailx_csrf" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("newPageData set no mailx_csrf cookie (%v)", rec.Result().Cookies())
	}
	if cookie.Value != data.CSRFToken {
		t.Errorf("cookie %q does not match the token embedded in the page %q", cookie.Value, data.CSRFToken)
	}

	s.render(rec, http.StatusOK, "users.html", data)

	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store: a cached page replays a stale form", cc)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `name="_csrf" value="`+data.CSRFToken+`"`) {
		t.Errorf("the Sign out form does not carry the token; body:\n%s", body)
	}

	bodyTag := ""
	if i := strings.Index(body, "<body"); i >= 0 {
		if j := strings.Index(body[i:], ">"); j > 0 {
			bodyTag = body[i : i+j+1]
		}
	}
	if !strings.Contains(bodyTag, "hx-headers=") || !strings.Contains(bodyTag, data.CSRFToken) {
		t.Errorf("hx-headers on <body> does not carry the token: %s", bodyTag)
	}
	if strings.Contains(bodyTag, `X-CSRF-Token":""`) {
		t.Errorf("hx-headers still ships an empty token: %s", bodyTag)
	}
	if !strings.Contains(body, "htmx:configRequest") {
		t.Error("layout.html does not sync X-CSRF-Token from the live cookie")
	}
}

// TestLogoutPostWithPageTokenPassesCSRF is the user-visible symptom of the
// un-migrated handlers: the "Sign out" button of a page rendered without a
// token answered "CSRF check failed: csrf token missing" instead of ending the
// session.
func TestLogoutPostWithPageTokenPassesCSRF(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	s := newTestServer(t, tmpl)
	s.csrf = auth.NewCSRFManager([]byte("test-signing-key"))

	mux := http.NewServeMux()
	mux.HandleFunc("POST /logout", s.handleLogout)
	h := s.csrf.Middleware(mux)

	// A page render is what hands the browser its token and cookie.
	pageRec := httptest.NewRecorder()
	data := s.newPageData(pageRec, httptest.NewRequest(http.MethodGet, "/", nil), "Dashboard", "dashboard", nil)

	var cookie *http.Cookie
	for _, c := range pageRec.Result().Cookies() {
		if c.Name == "mailx_csrf" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("page render set no mailx_csrf cookie")
	}

	body := url.Values{"_csrf": {data.CSRFToken}}
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("POST /logout was rejected by CSRF: status = %d, body %q", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusFound, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

var (
	// pageRenderRe finds a full page render and captures the template name.
	pageRenderRe = regexp.MustCompile(`s\.render\([^,]+,\s*[^,]+,\s*"([a-z_]+\.html)"`)
	// handBuiltPageDataRe finds the same call with a pageData literal built by
	// hand instead of by newPageData.
	handBuiltPageDataRe = regexp.MustCompile(`s\.render\([^,]+,\s*[^,]+,\s*"([a-z_]+\.html)"\s*,\s*pageData\{`)
)

// TestEveryPageRendererUsesNewPageData is the static guard for defect 2. Six
// handlers built pageData{...} inline instead of calling newPageData, so their
// pages shipped an empty token in the hx-headers on <body> *and* in the "Sign
// out" form: every write from /, /users, /users/{id}, /domains,
// /domains/{id} and /audit - including signing out - answered 403.
//
// renderError is the one allowed exception (error.html carries no request to
// read the token from, and layout.html fills its empty field from the cookie in
// the browser), and login.html is rendered through renderLogin, which ensures a
// token of its own.
func TestEveryPageRendererUsesNewPageData(t *testing.T) {
	files, err := filepath.Glob("handlers_*.go")
	if err != nil {
		t.Fatalf("glob handlers: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no handlers_*.go files found next to this test")
	}

	rendered := map[string]string{}
	var handBuilt []string
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range pageRenderRe.FindAllStringSubmatch(string(src), -1) {
			rendered[m[1]] = f
		}
		for _, m := range handBuiltPageDataRe.FindAllStringSubmatch(string(src), -1) {
			handBuilt = append(handBuilt, f+": "+m[1])
		}
	}
	if len(rendered) < len(pageTemplateNames)-1 {
		t.Fatalf("found only %d page renders (%v); the extractor regex is stale", len(rendered), rendered)
	}

	for _, page := range pageTemplateNames {
		if page == "error.html" {
			continue // renderError(w, status, msg) has no request to read a token from
		}
		if _, ok := rendered[page]; !ok {
			t.Errorf("no handler renders %s; if the page was removed, drop it from pageTemplateNames", page)
		}
	}

	for _, site := range handBuilt {
		t.Errorf("%s passes a hand-built pageData, so the page renders an empty CSRF token "+
			"and every write from it fails with 403; use s.newPageData(w, r, ...)", site)
	}
}
