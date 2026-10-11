package server

import (
	"net/http"
	"strconv"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
)

// currentSessionID is the id of the session the request is signed in with.
func (s *Server) currentSessionID(r *http.Request) string {
	if c, err := r.Cookie("mailx_session"); err == nil {
		return c.Value
	}
	return ""
}

// handleSessionsPage lists every active panel session. Requires sessions.manage.
func (s *Server) handleSessionsPage(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "sessions.manage") {
		return
	}
	sessions, err := s.sessions.List(r.Context(), 0)
	if err != nil {
		s.renderError(w, 500, "Failed to load sessions")
		return
	}
	s.render(w, 200, "sessions.html", s.newPageData(w, r, "Sessions", "sessions", map[string]any{
		"Sessions": sessions,
	}))
}

// handleSessionRevoke deletes a single session (admin, any admin).
func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.requirePermission(w, r, "sessions.manage") {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		s.renderError(w, 400, "Invalid session ID")
		return
	}
	if err := s.sessions.Delete(r.Context(), id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	sess := auth.SessionFromContext(r.Context())
	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: "admin:" + sess.Username, Action: "session.revoke", TargetType: "session",
		TargetID: id, Result: "ok", RemoteIP: clientIP(r),
	})
	w.Header().Set("HX-Redirect", "/system/sessions?flash="+encodeFlash("Session revoked"))
	w.WriteHeader(http.StatusOK)
}

// handleAccountSessionRevoke revokes one of the signed-in admin's own sessions.
func (s *Server) handleAccountSessionRevoke(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}
	id := r.PathValue("id")
	if id == "" || id == s.currentSessionID(r) {
		s.renderFormError(w, "You cannot revoke your current session")
		return
	}
	if err := s.sessions.Delete(r.Context(), id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/account?flash="+encodeFlash("Session revoked"))
	w.WriteHeader(http.StatusOK)
}

// handleAccountSessionsRevokeOthers signs the admin out of every other device.
func (s *Server) handleAccountSessionsRevokeOthers(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r.Context())
	if sess == nil {
		s.renderError(w, http.StatusUnauthorized, "Not signed in")
		return
	}
	n, err := s.sessions.DeleteForUser(r.Context(), sess.AdminUserID, s.currentSessionID(r))
	if err != nil {
		s.renderFormError(w, err.Error())
		return
	}
	w.Header().Set("HX-Redirect", "/account?flash="+encodeFlash(strconv.FormatInt(n, 10)+" session(s) revoked"))
	w.WriteHeader(http.StatusOK)
}
