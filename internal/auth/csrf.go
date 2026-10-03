package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

const (
	csrfCookieName = "mailx_csrf"
	csrfHeaderName = "X-CSRF-Token"
	csrfFormField  = "_csrf"
)

var (
	ErrCSRFMissing = errors.New("csrf token missing")
	ErrCSRFInvalid = errors.New("csrf token invalid")
)

// CSRFManager issues and validates CSRF tokens.
//
// Design: we issue a random token in a non-HttpOnly cookie (so JS can read it
// and inject it into HTMX requests via hx-headers). On every mutation we
// verify that the header (or form field) matches the cookie exactly.
//
// This is the "double-submit cookie" pattern. It works because an attacker
// on a different origin cannot read the cookie (SameSite=Lax + no CORS),
// so they cannot include the correct value in the forged request.
//
// The token is minted once per browser session and then reused for the whole
// lifetime of the cookie (see Ensure). It used to be re-minted on every single
// page render, which made the token of every *other* open tab/page stale the
// moment any page was loaded: the second render overwrote the one mailx_csrf
// cookie the browser has, so submitting the form you were looking at answered
//
//	CSRF check failed: csrf token invalid
//
// The browser holds exactly one cookie, so the server has to treat its value as
// the session's token instead of rotating it per response.
type CSRFManager struct {
	// Optional signing key for extra safety. If set, the token value is
	// HMAC'd before being placed in the cookie, so a leaked cookie value
	// doesn't help an attacker craft new tokens.
	key []byte
}

func NewCSRFManager(key []byte) *CSRFManager {
	return &CSRFManager{key: key}
}

// Issue generates a fresh token, sets it in the cookie, and returns it.
//
// Prefer Ensure: minting a token on every render is what broke the panel.
// Issue stays for the cases where a brand new token is genuinely wanted
// (tests, and the first render of a browser that has no cookie yet).
func (m *CSRFManager) Issue(w http.ResponseWriter) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	token := base64.RawURLEncoding.EncodeToString(raw)
	if len(m.key) > 0 {
		token = token + "." + sign(m.key, raw)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // JS must be able to read this for hx-headers
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   24 * 60 * 60,
	})

	return token, nil
}

// Ensure returns the token this browser already has, and only mints a new one
// when the request carries none (or carries one that did not come from us).
//
// Every page render must go through this instead of Issue: the browser stores
// exactly one mailx_csrf cookie, so re-issuing on each render silently
// invalidates the token embedded in every other page that is already open
// (second tab, HTMX partial target, browser back/forward cache, reload while
// typing) and those pages then answer
//
//	CSRF check failed: csrf token invalid
//
// Reusing the cookie keeps page markup, the cookie and the token that HTMX
// sends through hx-headers in agreement for the session's whole lifetime.
func (m *CSRFManager) Ensure(w http.ResponseWriter, r *http.Request) (string, error) {
	if tok := m.TokenFromCookie(r); m.valid(tok) {
		return tok, nil
	}
	return m.Issue(w)
}

// valid reports whether tok was minted by this manager. With a signing key
// configured a hand-made cookie value is rejected, so an attacker who can plant
// a cookie (a sibling host, a proxy) still cannot forge a matching pair.
func (m *CSRFManager) valid(tok string) bool {
	if tok == "" {
		return false
	}
	if len(m.key) == 0 {
		// No key configured (e.g. the settings row could not be loaded):
		// unsigned tokens cannot be told apart, accept any non-empty one.
		return true
	}
	raw, mac, ok := strings.Cut(tok, ".")
	if !ok {
		return false
	}
	body, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return false
	}
	return constantTimeEqual(mac, sign(m.key, body))
}

// sign returns the base64 HMAC-SHA256 of raw under key.
func sign(key, raw []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// TokenFromCookie reads the current token from the request.
// Templates use this to embed the token into page markup.
func (m *CSRFManager) TokenFromCookie(r *http.Request) string {
	c, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// Verify checks that the request carries a valid token.
//
// A plain <form> posts the token in _csrf while HTMX sends it in the
// X-CSRF-Token header, so either channel is accepted: whichever one matches the
// cookie is proof enough. (Letting the header win when it is present - even
// empty or stale - used to hide a perfectly valid form field.)
func (m *CSRFManager) Verify(r *http.Request) error {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return ErrCSRFMissing
	}
	if !m.valid(cookie.Value) {
		return ErrCSRFInvalid
	}

	header := r.Header.Get(csrfHeaderName)
	field := r.FormValue(csrfFormField)

	switch {
	case header != "" && constantTimeEqual(cookie.Value, header):
		return nil
	case field != "" && constantTimeEqual(cookie.Value, field):
		return nil
	case header == "" && field == "":
		return ErrCSRFMissing
	default:
		return ErrCSRFInvalid
	}
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// Middleware enforces CSRF on unsafe methods.
//
// Safe: GET, HEAD, OPTIONS
// Unsafe: everything else
func (m *CSRFManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The /api/ subtree authenticates with a bearer token, not the session
		// cookie, so the double-submit-cookie check below does not apply to it
		// and would only reject every legitimate API client.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		switch r.Method {
		case "GET", "HEAD", "OPTIONS":
			next.ServeHTTP(w, r)
			return
		}

		if err := m.Verify(r); err != nil {
			http.Error(w, "CSRF check failed: "+err.Error(), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
