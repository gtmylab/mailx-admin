package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

type ctxKey int

const sessionCtxKey ctxKey = 1

const (
	sessionCookieName = "mailx_session"

	// sessionLookupTimeout bounds the session lookup. This middleware runs
	// *before* any request budget — the routes that need a session are wrapped
	// around the budget — so a slow or locked database would otherwise hang
	// every URL, /login and /healthz included, without writing a single log
	// line. That is the "the panel just loads forever" report, seen from the
	// browser. A lookup that cannot complete in time is treated as "no
	// session": the request continues unauthenticated (the panel answers
	// /login, or redirects to it) and the reason goes to the log.
	sessionLookupTimeout = 5 * time.Second
)

func (s *SessionStore) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), sessionLookupTimeout)
		sess, err := s.Get(ctx, cookie.Value)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				slog.Warn("session lookup did not finish in time; treating the request as signed out",
					"timeout", sessionLookupTimeout.String(), "err", err)
			}
			// invalid/expired — clear cookie and continue unauthenticated
			clearSessionCookie(w)
			next.ServeHTTP(w, r)
			return
		}

		ctx = context.WithValue(r.Context(), sessionCtxKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func SessionFromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionCtxKey).(*Session)
	return s
}

// RequireAuth rejects unauthenticated requests.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if SessionFromContext(r.Context()) == nil {
			// HTMX requests want a redirect header, not a full HTML page
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", "/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func RequireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFromContext(r.Context())
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if sess.Role != role && sess.Role != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func setSessionCookie(w http.ResponseWriter, id string, expires int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// internal/auth/middleware.go

func RequireWrite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFromContext(r.Context())
		if sess == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if sess.Role == "readonly" {
			http.Error(w, "read-only account", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
