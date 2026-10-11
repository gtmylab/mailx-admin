package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/models"
)

// adminRoles and adminAccountTypes are the presets the admin form offers.
var adminRoles = []string{"superadmin", "admin", "operator", "readonly"}
var adminAccountTypes = []string{"panel", "system", "both"}

func (s *Server) handleAdminsPage(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "admin.manage") {
		return
	}
	admins, err := s.store.ListAdminUsers(r.Context())
	if err != nil {
		s.renderError(w, 500, "Failed to load admin users")
		return
	}
	groups, _ := s.store.ListAdminGroups(r.Context())
	s.render(w, 200, "admins.html", s.newPageData(w, r, "Admin users", "admins", map[string]any{
		"Admins": admins,
		"Groups": groups,
	}))
}

func (s *Server) handleAdminNew(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "admin.manage") {
		return
	}
	s.renderAdminForm(w, r, models.AdminUser{Active: true, Role: "operator", AccountType: "panel"})
}

func (s *Server) handleAdminEdit(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "admin.manage") {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid admin ID")
		return
	}
	a, err := s.store.GetAdminUser(r.Context(), id)
	if err != nil || a == nil {
		s.renderError(w, 404, "Admin not found")
		return
	}
	s.renderAdminForm(w, r, *a)
}

func (s *Server) renderAdminForm(w http.ResponseWriter, r *http.Request, a models.AdminUser) {
	groups, _ := s.store.ListAdminGroups(r.Context())
	s.renderPartial(w, "admin_form", map[string]any{
		"Admin":  a,
		"Groups": groups,
		"Roles":  adminRoles,
		"Types":  adminAccountTypes,
	})
}

func (s *Server) handleAdminSave(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "admin.manage") {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	role := r.FormValue("role")
	accountType := r.FormValue("account_type")
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	email := strings.TrimSpace(r.FormValue("email"))
	enabled := r.FormValue("enabled") == "1"
	ttl, _ := strconv.Atoi(r.FormValue("session_ttl_minutes"))
	groupID, _ := strconv.ParseInt(r.FormValue("group_id"), 10, 64)

	if username == "" {
		s.renderFormError(w, "Username is required")
		return
	}
	if !containsStr(adminRoles, role) {
		role = "operator"
	}
	if !containsStr(adminAccountTypes, accountType) {
		accountType = "panel"
	}

	ctx := r.Context()
	sess := auth.SessionFromContext(ctx)
	action := "admin.create"

	if idStr := r.FormValue("id"); idStr != "" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.renderFormError(w, "Invalid admin ID")
			return
		}
		if err := s.store.UpdateAdminUser(ctx, models.AdminUser{
			ID: id, Role: role, Active: enabled, DisplayName: displayName, Email: email,
			AccountType: accountType, SessionTTLMinutes: ttl, GroupID: groupID,
		}); err != nil {
			s.renderFormError(w, err.Error())
			return
		}
		action = "admin.update"
	} else {
		password := r.FormValue("password")
		if len(password) < 8 {
			s.renderFormError(w, "Password must be at least 8 characters")
			return
		}
		hash, err := auth.HashPassword(password)
		if err != nil {
			s.renderFormError(w, "Failed to hash password")
			return
		}
		if _, err := s.store.InsertAdminUser(ctx, models.AdminUser{
			Username: username, PasswordHash: hash, Role: role, Active: enabled,
			DisplayName: displayName, Email: email, AccountType: accountType,
			SessionTTLMinutes: ttl, GroupID: groupID,
		}); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				s.renderFormError(w, "Username already exists")
				return
			}
			s.renderFormError(w, err.Error())
			return
		}
	}

	_ = s.auditor.Log(ctx, audit.Entry{
		Actor: "admin:" + sess.Username, Action: action, TargetType: "admin_user",
		TargetID: username, Result: "ok", RemoteIP: clientIP(r),
	})
	w.Header().Set("HX-Redirect", "/system/admins?flash="+encodeFlash("Saved \""+username+"\""))
	w.WriteHeader(http.StatusOK)
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) handleAdminToggle(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "admin.manage") {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid admin ID")
		return
	}
	a, err := s.store.GetAdminUser(r.Context(), id)
	if err != nil || a == nil {
		s.renderError(w, 404, "Admin not found")
		return
	}
	if a.Username == "admin" {
		s.renderFormError(w, "The primary admin account cannot be disabled")
		return
	}
	if err := s.store.SetAdminUserActive(r.Context(), id, !a.Active); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/system/admins")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "admin.manage") {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid admin ID")
		return
	}
	a, err := s.store.GetAdminUser(r.Context(), id)
	if err != nil || a == nil {
		s.renderError(w, 404, "Admin not found")
		return
	}
	if a.Username == "admin" {
		s.renderFormError(w, "The primary admin account cannot be deleted")
		return
	}
	if err := s.store.DeleteAdminUser(r.Context(), id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/system/admins?flash="+encodeFlash("Admin removed"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAdminResetPasswordForm(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "admin.manage") {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid admin ID")
		return
	}
	s.renderPartial(w, "admin_reset_password", map[string]any{"ID": id})
}

func (s *Server) handleAdminResetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "admin.manage") {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid admin ID")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	password := r.FormValue("password")
	if len(password) < 8 {
		s.renderFormError(w, "Password must be at least 8 characters")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.renderFormError(w, "Failed to hash password")
		return
	}
	if err := s.store.SetAdminUserPassword(r.Context(), id, hash); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/system/admins?flash="+encodeFlash("Password reset"))
	w.WriteHeader(http.StatusOK)
}
