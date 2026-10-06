package server

import (
	"net/http"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
)

// accountView is the model for the signed-in admin's own Account page.
type accountView struct {
	Username    string
	Role        string
	TotpEnabled bool
}

func (s *Server) handleAccountPage(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}

	v := accountView{Username: sess.Username, Role: sess.Role}
	var totp int
	_ = s.db.QueryRowContext(r.Context(), `SELECT totp_enabled FROM admin_users WHERE id = ?`, sess.AdminUserID).Scan(&totp)
	v.TotpEnabled = totp == 1

	s.render(w, 200, "account.html", s.newPageData(w, r, "Account", "account", map[string]any{
		"Account": v,
	}))
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
