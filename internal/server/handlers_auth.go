package server

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
)

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if auth.SessionFromContext(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.renderLogin(w, http.StatusOK, "", false)
}

// renderLogin renders login.html with a freshly issued CSRF token.
//
// login.html is a plain (non-HTMX) form and POST /login sits behind the global
// CSRF middleware (see buildRouter), so the token cannot come from the layout's
// hx-headers: it has to travel in a hidden form field, with the matching
// double-submit cookie set on the same response. Issuing a token on every
// render - including the error re-renders below - is what keeps a login retry
// after a typo from failing with "csrf token missing".
func (s *Server) renderLogin(w http.ResponseWriter, status int, errMsg string, totpRequired bool) {
	token, err := s.csrf.Issue(w)
	if err != nil {
		s.logger.Error("issue csrf token", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	s.render(w, status, "login.html", map[string]any{
		"Error":        errMsg,
		"TOTPRequired": totpRequired,
		"CSRFToken":    token,
	})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, http.StatusBadRequest, "Invalid form", false)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	totp := strings.TrimSpace(r.FormValue("totp"))

	if username == "" || password == "" {
		s.renderLogin(w, http.StatusBadRequest, "Username and password required", false)
		return
	}

	ctx := r.Context()

	var (
		id          int64
		hash        string
		totpSecret  sql.NullString
		totpEnabled int
		active      int
	)

	err := s.db.QueryRowContext(ctx, `
        SELECT id, password_hash, totp_secret, totp_enabled, active
        FROM admin_users WHERE username = ?
    `, username).Scan(&id, &hash, &totpSecret, &totpEnabled, &active)

	if err == sql.ErrNoRows || active != 1 {
		s.auditLogin(ctx, username, "error", "unknown user")
		s.renderLogin(w, http.StatusUnauthorized, "Invalid credentials", false)
		return
	}
	if err != nil {
		s.logger.Error("login query", "err", err)
		s.renderLogin(w, http.StatusInternalServerError, "Internal error", false)
		return
	}

	ok, err := auth.VerifyPassword(password, hash)
	if err != nil || !ok {
		s.auditLogin(ctx, username, "error", "bad password")
		s.renderLogin(w, http.StatusUnauthorized, "Invalid credentials", false)
		return
	}

	// TOTP check
	if totpEnabled == 1 {
		if totp == "" {
			s.renderLogin(w, http.StatusOK, "", true)
			return
		}
		if !totpSecret.Valid || !auth.VerifyTOTP(totpSecret.String, totp) {
			s.auditLogin(ctx, username, "error", "bad totp")
			s.renderLogin(w, http.StatusUnauthorized, "Invalid 2FA code", true)
			return
		}
	}

	// Create session
	sess, err := s.sessions.Create(ctx, id, r.UserAgent(), clientIP(r))
	if err != nil {
		s.logger.Error("create session", "err", err)
		s.renderLogin(w, http.StatusInternalServerError, "Internal error", false)
		return
	}

	// Update last login
	_, _ = s.db.ExecContext(ctx, `UPDATE admin_users SET last_login = ? WHERE id = ?`, time.Now(), id)

	s.auditLogin(ctx, username, "ok", "")

	http.SetCookie(w, &http.Cookie{
		Name:     "mailx_session",
		Value:    sess.ID,
		Path:     "/",
		MaxAge:   int(time.Until(sess.ExpiresAt).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("mailx_session"); err == nil {
		_ = s.sessions.Delete(r.Context(), cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: "mailx_session", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) auditLogin(ctx context.Context, username, result, reason string) {
	_ = s.auditor.Log(ctx, audit.Entry{
		Actor:      "admin:" + username,
		Action:     "auth.login",
		TargetType: "admin_user",
		TargetID:   username,
		Result:     result,
		Detail:     map[string]any{"reason": reason},
	})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	return host
}
