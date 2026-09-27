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
	s.render(w, http.StatusOK, "login.html", map[string]any{
		"Error": nil,
	})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.render(w, 400, "login.html", map[string]any{"Error": "Invalid form"})
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	totp := strings.TrimSpace(r.FormValue("totp"))

	if username == "" || password == "" {
		s.render(w, 400, "login.html", map[string]any{"Error": "Username and password required"})
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
		s.render(w, 401, "login.html", map[string]any{"Error": "Invalid credentials"})
		return
	}
	if err != nil {
		s.logger.Error("login query", "err", err)
		s.render(w, 500, "login.html", map[string]any{"Error": "Internal error"})
		return
	}

	ok, err := auth.VerifyPassword(password, hash)
	if err != nil || !ok {
		s.auditLogin(ctx, username, "error", "bad password")
		s.render(w, 401, "login.html", map[string]any{"Error": "Invalid credentials"})
		return
	}

	// TOTP check
	if totpEnabled == 1 {
		if totp == "" {
			s.render(w, 200, "login.html", map[string]any{
				"Error":        nil,
				"TOTPRequired": true,
			})
			return
		}
		if !totpSecret.Valid || !auth.VerifyTOTP(totpSecret.String, totp) {
			s.auditLogin(ctx, username, "error", "bad totp")
			s.render(w, 401, "login.html", map[string]any{
				"Error":        "Invalid 2FA code",
				"TOTPRequired": true,
			})
			return
		}
	}

	// Create session
	sess, err := s.sessions.Create(ctx, id, r.UserAgent(), clientIP(r))
	if err != nil {
		s.logger.Error("create session", "err", err)
		s.render(w, 500, "login.html", map[string]any{"Error": "Internal error"})
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
