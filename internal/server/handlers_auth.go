package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
)

const (
	// loginLockoutMax is the number of failed attempts before a username is
	// temporarily locked out.
	loginLockoutMax = 5
	// loginLockoutWindow is the period over which failures are counted.
	loginLockoutWindow = 15 * time.Minute
)

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if auth.SessionFromContext(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.renderLogin(w, r, http.StatusOK, loginPage{})
}

// loginPage is what login.html renders.
//
// TOTPRequired switches the form from username+password to the code step, and
// Challenge is what carries "this password was already checked" across the two
// requests. Before that existed, the second step was a second full login: the
// form came back empty, the operator retyped the password, and the whole
// handler ran twice -- which is how a two-factor sign-in could end in the
// password path's "Internal error" and still look like a 2FA bug.
type loginPage struct {
	Error        string
	TOTPRequired bool
	Challenge    string
	Username     string
}

// Messages for the two ways the panel itself can fail during a sign-in. They
// say what happened and what to do; "Internal error" said neither, and it is
// the message the two-factor report was written about.
const (
	loginLookupFailed = "The panel could not read its own database, so signing in is not possible right now. " +
		"Check the service log, or run `mailx-admin doctor`."
	loginSessionFailed = "Your credentials were correct, but the panel could not store the session. " +
		"Try again in a moment; if it keeps failing, check `mailx-admin doctor`."
)

// renderLogin renders login.html with the session's CSRF token.
//
// login.html is a plain (non-HTMX) form and POST /login sits behind the global
// CSRF middleware (see buildRouter), so the token cannot come from the layout's
// hx-headers: it has to travel in a hidden form field, with the matching
// double-submit cookie set on the same response.
//
// The token is taken from the cookie when the browser already has one (Ensure),
// and only minted when there is none. Re-issuing it on every render - including
// the error re-renders below - is what used to make a second tab, a reload or a
// password manager re-fetching /login answer
//
//	CSRF check failed: csrf token invalid
//
// because the browser keeps just one mailx_csrf cookie and the newest render
// overwrote the token still embedded in the form the user was looking at.
func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, page loginPage) {
	token, err := s.csrf.Ensure(w, r)
	if err != nil {
		s.logger.Error("login page: ensure csrf token", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	s.render(w, status, "login.html", map[string]any{
		"Error":        page.Error,
		"TOTPRequired": page.TOTPRequired,
		"Challenge":    page.Challenge,
		"Username":     page.Username,
		"CSRFToken":    token,
	})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, r, http.StatusBadRequest, loginPage{Error: "Invalid form"})
		return
	}

	// The second factor has its own step. The challenge token is the proof that
	// the password was already verified, so the code step carries no password:
	// nothing here can be replayed into a fresh password check, and an expired
	// token sends the operator back to the start instead of into a loop.
	if challenge := strings.TrimSpace(r.FormValue("challenge")); challenge != "" {
		s.handleTOTPSubmit(w, r, challenge)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	totp := strings.TrimSpace(r.FormValue("totp"))

	if username == "" || password == "" {
		s.renderLogin(w, r, http.StatusBadRequest, loginPage{Error: "Username and password required"})
		return
	}

	ctx := r.Context()
	ip := clientIP(r)

	// Brute-force lockout: too many recent failures for this username.
	if n, _ := s.store.CountRecentFailedLogins(ctx, username, time.Now().Add(-loginLockoutWindow)); n >= loginLockoutMax {
		s.auditLogin(ctx, username, "error", "locked out")
		go s.DispatchNotifications(context.Background(), "auth.lockout", map[string]string{"username": username, "ip": ip})
		s.renderLogin(w, r, http.StatusTooManyRequests, loginPage{Error: "Too many failed attempts. Try again in a few minutes."})
		return
	}

	var (
		id          int64
		hash        string
		totpSecret  sql.NullString
		totpEnabled int
		active      int
		ttlMinutes  sql.NullInt64
	)

	err := s.db.QueryRowContext(ctx, `
        SELECT id, password_hash, totp_secret, totp_enabled, active, session_ttl_minutes
        FROM admin_users WHERE username = ?
    `, username).Scan(&id, &hash, &totpSecret, &totpEnabled, &active, &ttlMinutes)

	if err == sql.ErrNoRows || active != 1 {
		_ = s.store.RecordLoginAttempt(ctx, username, ip, false)
		s.auditLogin(ctx, username, "error", "unknown user")
		s.renderLogin(w, r, http.StatusUnauthorized, loginPage{Error: "Invalid credentials"})
		return
	}
	if err != nil {
		// Without the username and the wrapped error this line said nothing an
		// operator could act on -- and this is the query that decides whether
		// anybody can sign in at all.
		s.logger.Error("login: admin lookup failed", "username", username, "ip", ip, "err", err)
		s.renderLogin(w, r, http.StatusInternalServerError, loginPage{Error: loginLookupFailed})
		return
	}

	ok, err := auth.VerifyPassword(password, hash)
	if err != nil || !ok {
		_ = s.store.RecordLoginAttempt(ctx, username, ip, false)
		s.auditLogin(ctx, username, "error", "bad password")
		go s.DispatchNotifications(context.Background(), "auth.login_failed", map[string]string{"username": username, "ip": ip})
		s.renderLogin(w, r, http.StatusUnauthorized, loginPage{Error: "Invalid credentials"})
		return
	}

	// TOTP check
	if totpEnabled == 1 {
		// An account with 2FA enabled but no secret can never sign in. Asking
		// for a code nothing can verify produces "Invalid 2FA code" forever,
		// which reads as "you typed it wrong" instead of "this account is
		// misconfigured" -- so say which it is.
		if !totpSecret.Valid || strings.TrimSpace(totpSecret.String) == "" {
			s.logger.Error("login: 2fa enabled without a secret",
				"username", username, "admin_id", id, "ip", ip)
			s.renderLogin(w, r, http.StatusInternalServerError, loginPage{
				Error: "Two-factor authentication is enabled for this account but no secret is stored, " +
					"so no code can be verified. An administrator has to set up 2FA for this account again.",
				Username: username,
			})
			return
		}

		// A code sent in the same request (an already-open tab, a script that
		// posts everything at once) is still accepted -- but the normal path is
		// the challenge below, so the password is not posted twice.
		if totp == "" {
			token, err := s.pendingLoginStore().Put(pendingLogin{
				AdminID:  id,
				Username: username,
			})
			if err != nil {
				s.logger.Error("login: create 2fa challenge", "username", username, "ip", ip, "err", err)
				s.renderLogin(w, r, http.StatusServiceUnavailable, loginPage{
					Error: "Too many sign-ins are waiting for their second factor. Try again in a minute.",
				})
				return
			}
			s.renderLogin(w, r, http.StatusOK, loginPage{
				TOTPRequired: true,
				Challenge:    token,
				Username:     username,
			})
			return
		}
		if !auth.VerifyTOTP(totpSecret.String, totp) {
			s.recordBadTOTP(ctx, username, ip)
			s.renderLogin(w, r, http.StatusUnauthorized, loginPage{Error: "Invalid 2FA code"})
			return
		}
	}

	// Create session (per-user TTL, then global setting, then the 24h default).
	s.startSession(w, r, id, username, ttlMinutes)
}

// handleTOTPSubmit completes a sign-in whose password was already verified.
//
// The challenge is single-use: taking it out of the store is what proves the
// password check happened, so a replayed form cannot mint a second session and
// an expired one asks for the password again instead of looping.
func (s *Server) handleTOTPSubmit(w http.ResponseWriter, r *http.Request, challenge string) {
	ctx := r.Context()
	ip := clientIP(r)

	pending, ok := s.pendingLoginStore().Take(challenge)
	if !ok {
		s.renderLogin(w, r, http.StatusUnauthorized, loginPage{
			Error: "That sign-in session has expired. Enter your username and password again.",
		})
		return
	}

	// Re-read the account: a challenge issued before somebody disabled it must
	// not finish the sign-in for them.
	var (
		active      int
		totpEnabled int
		secret      sql.NullString
		ttlMinutes  sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, `
        SELECT active, totp_enabled, totp_secret, session_ttl_minutes
        FROM admin_users WHERE id = ?
    `, pending.AdminID).Scan(&active, &totpEnabled, &secret, &ttlMinutes)
	if err == sql.ErrNoRows || (err == nil && active != 1) {
		s.renderLogin(w, r, http.StatusUnauthorized, loginPage{
			Error: "This account is no longer allowed to sign in.",
		})
		return
	}
	if err != nil {
		s.logger.Error("login: 2fa account lookup failed",
			"username", pending.Username, "admin_id", pending.AdminID, "ip", ip, "err", err)
		s.renderLogin(w, r, http.StatusInternalServerError, loginPage{Error: loginLookupFailed})
		return
	}
	if totpEnabled != 1 || !secret.Valid || strings.TrimSpace(secret.String) == "" {
		// 2FA was turned off (or broken) between the two steps. The password
		// was correct, but the proof is stale: start over.
		s.renderLogin(w, r, http.StatusUnauthorized, loginPage{
			Error: "Two-factor authentication changed while you were signing in. Please sign in again.",
		})
		return
	}

	code := strings.TrimSpace(r.FormValue("totp"))
	if code == "" || !auth.VerifyTOTP(secret.String, code) {
		s.recordBadTOTP(ctx, pending.Username, ip)

		pending.Attempts++
		if pending.Attempts >= maxTOTPAttempts {
			// Same ceiling the password path has: proving the password again is
			// cheaper for the operator than a locked-out account, and it stops
			// one verified password from brute-forcing six digits.
			s.renderLogin(w, r, http.StatusUnauthorized, loginPage{
				Error: "Too many incorrect codes. Sign in again from the beginning.",
			})
			return
		}

		// Hand out a fresh challenge so a typo does not cost the password.
		token, err := s.pendingLoginStore().Put(pending)
		if err != nil {
			s.logger.Error("login: renew 2fa challenge", "username", pending.Username, "ip", ip, "err", err)
			s.renderLogin(w, r, http.StatusUnauthorized, loginPage{
				Error: "That code is not valid. Sign in again from the beginning.",
			})
			return
		}
		s.renderLogin(w, r, http.StatusUnauthorized, loginPage{
			Error:        fmt.Sprintf("That code is not valid (%d of %d tries). Check that your phone's clock is correct.", pending.Attempts, maxTOTPAttempts),
			TOTPRequired: true,
			Challenge:    token,
			Username:     pending.Username,
		})
		return
	}

	s.startSession(w, r, pending.AdminID, pending.Username, ttlMinutes)
}

// pendingLoginStore returns the in-memory store of password-verified sign-ins,
// creating it on first use so a Server built by hand (tests) still works.
func (s *Server) pendingLoginStore() *pendingLogins {
	s.pendingOnce.Do(func() {
		if s.pending == nil {
			s.pending = newPendingLogins(pendingLoginTTL)
		}
	})
	return s.pending
}

// recordBadTOTP counts one wrong code: the lockout counter and the audit trail
// see it exactly like a wrong password, so a stolen password plus a guessing
// attacker is still limited.
func (s *Server) recordBadTOTP(ctx context.Context, username, ip string) {
	_ = s.store.RecordLoginAttempt(ctx, username, ip, false)
	s.auditLogin(ctx, username, "error", "bad totp")
	go s.DispatchNotifications(context.Background(), "auth.login_failed",
		map[string]string{"username": username, "ip": ip})
}

// startSession mints the session, sets the cookie and redirects. Both login
// paths go through it so the cookie flags, the audit entry and the "last login"
// stamp cannot drift apart.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, id int64, username string, ttlMinutes sql.NullInt64) {
	ctx := r.Context()
	ip := clientIP(r)

	sess, err := s.sessions.CreateWithTTL(ctx, id, s.sessionTTL(ctx, ttlMinutes), r.UserAgent(), ip)
	if err != nil {
		// The wrapped error is the only thing that says why -- a locked
		// database, a `sessions` table the migrations never created -- and it
		// used to be logged without the username that was signing in.
		s.logger.Error("login: create session failed",
			"username", username, "admin_id", id, "ip", ip, "err", err)
		s.renderLogin(w, r, http.StatusInternalServerError, loginPage{Error: loginSessionFailed})
		return
	}

	// Update last login
	_, _ = s.db.ExecContext(ctx, `UPDATE admin_users SET last_login = ? WHERE id = ?`, time.Now(), id)

	_ = s.store.RecordLoginAttempt(ctx, username, ip, true)
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
	// Close any interactive terminal session this admin has open.
	if sess := auth.SessionFromContext(r.Context()); sess != nil && s.terminals != nil {
		s.terminals.Destroy(sess.AdminUserID)
	}
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

// sessionTTL resolves the session lifetime for an admin: the per-user override
// when set, otherwise the global session_ttl_minutes setting, otherwise 24h.
func (s *Server) sessionTTL(ctx context.Context, perUser sql.NullInt64) time.Duration {
	if perUser.Valid && perUser.Int64 > 0 {
		return time.Duration(perUser.Int64) * time.Minute
	}
	var v string
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'session_ttl_minutes'`).Scan(&v)
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
		return time.Duration(n) * time.Minute
	}
	return 24 * time.Hour
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
