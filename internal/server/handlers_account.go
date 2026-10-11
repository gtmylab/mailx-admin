package server

import (
	"encoding/base64"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/models"
)

// accountView is the model for the signed-in admin's own Account page.
type accountView struct {
	Username         string
	Role             string
	DisplayName      string
	Email            string
	TotpEnabled      bool
	SessionTTL       int // global session_ttl_minutes (0 = default 24h)
	Notifications    []models.AdminNotification
	Sessions         []auth.Session
	CurrentSessionID string
}

func (s *Server) handleAccountPage(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}

	a, err := s.store.GetAdminUser(r.Context(), sess.AdminUserID)
	if err != nil || a == nil {
		s.renderError(w, http.StatusInternalServerError, "Failed to load account")
		return
	}

	var ttlStr string
	_ = s.db.QueryRowContext(r.Context(), `SELECT value FROM settings WHERE key = 'session_ttl_minutes'`).Scan(&ttlStr)
	ttl, _ := strconv.Atoi(strings.TrimSpace(ttlStr))

	notifications, _ := s.store.ListAdminNotifications(r.Context(), sess.AdminUserID)
	sessions, _ := s.sessions.List(r.Context(), sess.AdminUserID)

	v := accountView{
		Username:         sess.Username,
		Role:             sess.Role,
		DisplayName:      a.DisplayName,
		Email:            a.Email,
		TotpEnabled:      a.TotpEnabled,
		SessionTTL:       ttl,
		Notifications:    notifications,
		Sessions:         sessions,
		CurrentSessionID: s.currentSessionID(r),
	}
	s.render(w, 200, "account.html", s.newPageData(w, r, "Account", "account", map[string]any{
		"Account": v,
	}))
}

// handleAccountProfile updates the signed-in admin's display name and email.
func (s *Server) handleAccountProfile(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	email := strings.TrimSpace(r.FormValue("email"))

	a, err := s.store.GetAdminUser(r.Context(), sess.AdminUserID)
	if err != nil || a == nil {
		s.renderFormError(w, "Account not found")
		return
	}
	a.DisplayName = displayName
	a.Email = email
	if err := s.store.UpdateAdminUser(r.Context(), *a); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/account?flash="+encodeFlash("Profile saved"))
	w.WriteHeader(http.StatusOK)
}

// handleAccountTOTPSetup generates a secret (stored but not yet enabled) and
// returns the provisioning QR/URI and secret for the authenticator app.
func (s *Server) handleAccountTOTPSetup(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	qr, err := auth.TOTPQRPNG(sess.Username, "mailx-admin", secret, 200)
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	// Store the secret, but keep 2FA disabled until the code is confirmed.
	if err := s.store.SetAdminUserTOTP(r.Context(), sess.AdminUserID, secret, false); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	s.renderPartial(w, "totp_setup", map[string]any{
		// template.URL stops html/template from URL-escaping the base64 (which
		// contains '+' and '/') and corrupting the data URI.
		"QR":     template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(qr)),
		"Secret": secret,
	})
}

// handleAccountTOTPConfirm verifies the 6-digit code and enables 2FA.
func (s *Server) handleAccountTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	a, err := s.store.GetAdminUser(r.Context(), sess.AdminUserID)
	if err != nil || a == nil {
		s.renderFormError(w, "Account not found")
		return
	}
	if !auth.VerifyTOTP(a.TotpSecret, code) {
		s.renderFormError(w, "Invalid code")
		return
	}
	if err := s.store.SetAdminUserTOTP(r.Context(), sess.AdminUserID, a.TotpSecret, true); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: "admin:" + sess.Username, Action: "auth.totp_enable", TargetType: "admin_user",
		TargetID: sess.Username, Result: "ok", RemoteIP: clientIP(r),
	})
	w.Header().Set("HX-Redirect", "/account?flash="+encodeFlash("Two-factor authentication enabled"))
	w.WriteHeader(http.StatusOK)
}

// handleAccountTOTPDisable turns 2FA off and clears the secret.
func (s *Server) handleAccountTOTPDisable(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}
	if err := s.store.SetAdminUserTOTP(r.Context(), sess.AdminUserID, "", false); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: "admin:" + sess.Username, Action: "auth.totp_disable", TargetType: "admin_user",
		TargetID: sess.Username, Result: "ok", RemoteIP: clientIP(r),
	})
	w.Header().Set("HX-Redirect", "/account?flash="+encodeFlash("Two-factor authentication disabled"))
	w.WriteHeader(http.StatusOK)
}

// handleAccountSessionTTL sets the global session lifetime (minutes). Admin only.
func (s *Server) handleAccountSessionTTL(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}
	if !s.hasPermission(r.Context(), sess, "settings.write") {
		s.renderFormError(w, "You do not have permission to change the session timeout")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	minutes, err := strconv.Atoi(r.FormValue("session_ttl_minutes"))
	if err != nil || minutes < 0 {
		s.renderFormError(w, "Session timeout must be a number of minutes")
		return
	}
	upsertSetting(r.Context(), s.db, "session_ttl_minutes", strconv.Itoa(minutes))
	w.Header().Set("HX-Redirect", "/account?flash="+encodeFlash("Session timeout saved"))
	w.WriteHeader(http.StatusOK)
}

// handleChangePassword lets the signed-in admin change their own panel password,
// after proving they know the current one. It updates admin_users, not the
// mailbox users table.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderPartial(w, "form_error", map[string]any{"Error": "Invalid form data"})
		return
	}

	current := r.FormValue("current_password")
	next := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if current == "" || next == "" {
		s.renderPartial(w, "form_error", map[string]any{"Error": "Current and new passwords are required"})
		return
	}
	if len(next) < 8 {
		s.renderPartial(w, "form_error", map[string]any{"Error": "New password must be at least 8 characters"})
		return
	}
	if next != confirm {
		s.renderPartial(w, "form_error", map[string]any{"Error": "New passwords do not match"})
		return
	}

	var hash string
	if err := s.db.QueryRowContext(r.Context(), `SELECT password_hash FROM admin_users WHERE id = ?`, sess.AdminUserID).Scan(&hash); err != nil {
		s.renderPartial(w, "form_error", map[string]any{"Error": "Account not found"})
		return
	}
	if ok, err := auth.VerifyPassword(current, hash); err != nil || !ok {
		s.renderPartial(w, "form_error", map[string]any{"Error": "Current password is incorrect"})
		return
	}

	newHash, err := auth.HashPassword(next)
	if err != nil {
		s.renderPartial(w, "form_error", map[string]any{"Error": "Failed to hash the new password"})
		return
	}
	if _, err := s.db.ExecContext(r.Context(), `UPDATE admin_users SET password_hash = ? WHERE id = ?`, newHash, sess.AdminUserID); err != nil {
		s.renderPartial(w, "form_error", map[string]any{"Error": "Failed to update the password"})
		return
	}

	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: "admin:" + sess.Username, Action: "auth.change_password", TargetType: "admin_user", TargetID: sess.Username,
		Result: "ok", RemoteIP: clientIP(r),
	})

	s.renderPartial(w, "password_changed", map[string]any{})
}
