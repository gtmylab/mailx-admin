package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/models"
)

var notificationProviders = []string{"slack", "telegram", "discord", "email", "webhook"}

// ownNotification reports whether the notification id belongs to the admin.
func (s *Server) ownNotification(r *http.Request, adminUserID, id int64) bool {
	notes, _ := s.store.ListAdminNotifications(r.Context(), adminUserID)
	for _, n := range notes {
		if n.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) handleAccountNotificationAdd(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	provider := strings.TrimSpace(r.FormValue("provider"))
	target := strings.TrimSpace(r.FormValue("target"))
	events := strings.TrimSpace(r.FormValue("events"))

	if !containsStr(notificationProviders, provider) {
		s.renderFormError(w, "Unknown provider")
		return
	}
	if target == "" {
		s.renderFormError(w, "Target is required")
		return
	}

	eventList := splitAndTrim(events)
	eventsJSON, _ := json.Marshal(eventList)

	if _, err := s.store.InsertAdminNotification(r.Context(), models.AdminNotification{
		AdminUserID: sess.AdminUserID,
		Provider:    provider,
		Target:      target,
		Events:      string(eventsJSON),
		Active:      true,
	}); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/account?flash="+encodeFlash("Notification added"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAccountNotificationToggle(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderFormError(w, "Invalid notification ID")
		return
	}
	if !s.ownNotification(r, sess.AdminUserID, id) {
		s.renderFormError(w, "Notification not found")
		return
	}
	notes, _ := s.store.ListAdminNotifications(r.Context(), sess.AdminUserID)
	var cur bool
	for _, n := range notes {
		if n.ID == id {
			cur = n.Active
			break
		}
	}
	if err := s.store.SetAdminNotificationActive(r.Context(), id, !cur); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/account")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAccountNotificationDelete(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderFormError(w, "Invalid notification ID")
		return
	}
	if !s.ownNotification(r, sess.AdminUserID, id) {
		s.renderFormError(w, "Notification not found")
		return
	}
	if err := s.store.DeleteAdminNotification(r.Context(), id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/account?flash="+encodeFlash("Notification removed"))
	w.WriteHeader(http.StatusOK)
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
