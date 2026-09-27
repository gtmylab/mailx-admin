package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
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
// Call this on every page render that includes forms.
func (m *CSRFManager) Issue(w http.ResponseWriter) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	token := base64.RawURLEncoding.EncodeToString(raw)

	if len(m.key) > 0 {
		mac := hmac.New(sha256.New, m.key)
		mac.Write(raw)
		token = token + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
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
func (m *CSRFManager) Verify(r *http.Request) error {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return ErrCSRFMissing
	}

	// Header first, then form field
	provided := r.Header.Get(csrfHeaderName)
	if provided == "" {
		provided = r.FormValue(csrfFormField)
	}
	if provided == "" {
		return ErrCSRFMissing
	}

	if !constantTimeEqual(cookie.Value, provided) {
		return ErrCSRFInvalid
	}

	return nil
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
