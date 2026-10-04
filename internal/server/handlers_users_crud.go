package server

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/mutations"
)

// ---- New user form (rendered into a modal) ----

func (s *Server) handleUserNew(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		s.renderError(w, 500, "Failed to load state")
		return
	}

	s.renderPartial(w, "user_form", map[string]any{
		"Domains": snap.Domains,
		"User":    nil,
		"Action":  "/users",
		"Method":  "POST",
	})
}

// ---- Create ----

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}

	domainID, _ := strconv.ParseInt(r.FormValue("domain_id"), 10, 64)
	quota, _ := strconv.Atoi(r.FormValue("quota_mb"))
	isAdmin := r.FormValue("is_admin") == "on"

	input := mutations.CreateUserInput{
		DomainID:    domainID,
		Username:    r.FormValue("username"),
		Password:    r.FormValue("password"),
		QuotaMB:     quota,
		IsAdmin:     isAdmin,
		DisplayName: r.FormValue("display_name"),
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	res, email, err := s.mutations.CreateUser(r.Context(), actor, input)
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	// Warnings (for example a Roundcube seed that failed) go to the journal as
	// well as the toast, so they are diagnosable from the server side.
	for _, warning := range res.Warnings {
		s.logger.Warn("user create warning", "email", email, "warning", warning)
	}

	// Best-effort welcome mail, sent after the queued sync renders the mailbox.
	go s.sendWelcomeEmailAfterSync(email)

	// Success: redirect the whole page and show a toast. Any warnings (for
	// example a Roundcube seed that failed) ride along so the operator sees
	// them instead of finding out later from the mailbox owner.
	// HTMX handles HX-Redirect by doing a full navigation, so the toast
	// needs to survive. We use a flash message via query param.
	msg := "User " + email + " created"
	if len(res.Warnings) > 0 {
		msg += " — " + strings.Join(res.Warnings, "; ")
	}
	w.Header().Set("HX-Redirect", "/users?flash="+encodeFlash(msg))
	w.WriteHeader(http.StatusOK)
}

// ---- Edit form ----

func (s *Server) handleUserEdit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid user ID")
		return
	}

	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		s.renderError(w, 500, "Failed to load state")
		return
	}

	var user *models.User
	for i := range snap.Users {
		if snap.Users[i].ID == id {
			user = &snap.Users[i]
			break
		}
	}
	if user == nil {
		s.renderError(w, 404, "User not found")
		return
	}

	s.renderPartial(w, "user_form", map[string]any{
		"Domains": snap.Domains,
		"User":    user,
		"Action":  "/users/" + strconv.FormatInt(id, 10),
		"Method":  "PATCH",
	})
}

// ---- Update (quota, active, admin) ----

func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid user ID")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}

	in := mutations.UpdateUserInput{UserID: id}

	if v := r.FormValue("quota_mb"); v != "" {
		q, _ := strconv.Atoi(v)
		in.QuotaMB = &q
	}
	if v := r.FormValue("active"); v != "" {
		b := v == "on" || v == "true" || v == "1"
		in.Active = &b
	}
	if v := r.FormValue("is_admin"); v != "" {
		b := v == "on" || v == "true" || v == "1"
		in.IsAdmin = &b
	}
	if v := r.FormValue("display_name"); v != "" {
		in.DisplayName = &v
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.UpdateUser(r.Context(), actor, in); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/users?flash="+encodeFlash("User updated"))
	w.WriteHeader(http.StatusOK)
}

// ---- Delete ----

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid user ID")
		return
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.DeleteUser(r.Context(), actor, id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/users?flash="+encodeFlash("User deleted"))
	w.WriteHeader(http.StatusOK)
}

// ---- Reset password ----

func (s *Server) handleUserResetPassword(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid user ID")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}

	newPassword := r.FormValue("password")
	sendTo := r.FormValue("send_to") // optional alternate address

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	res, err := s.mutations.ResetUserPassword(r.Context(), actor, mutations.ResetPasswordInput{
		UserID:   id,
		Password: newPassword,
	})
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	for _, warning := range res.Warnings {
		s.logger.Warn("password reset warning", "user_id", id, "warning", warning)
	}

	// Optional: email the new password to an alternate address
	if sendTo != "" {
		if err := s.sendPasswordEmail(r.Context(), id, newPassword, sendTo); err != nil {
			s.logger.Warn("password email failed", "err", err)
		}
	}

	// Return a modal fragment telling the admin to copy the password
	s.renderPartial(w, "password_reveal", map[string]any{
		"Password": newPassword,
	})
}

// renderFormError returns a small fragment that HTMX swaps into the modal,
// showing the error and keeping the form intact.
func (s *Server) renderFormError(w http.ResponseWriter, msg string) {
	w.Header().Set("HX-Retarget", "#form-error")
	s.renderPartial(w, "form_error", map[string]any{"Error": msg})
}

func encodeFlash(msg string) string {
	return url.QueryEscape(msg)
}

// internal/server/handlers_users_crud.go

func (s *Server) handleUserResetPasswordForm(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid user ID")
		return
	}
	s.renderPartial(w, "password_form", map[string]any{
		"UserID": id,
	})
}
