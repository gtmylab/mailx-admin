package server

import (
	"bytes"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/version"
	"net/http"
)

// render executes a named template into a buffer first, so a template error
// doesn't send a half-rendered page with a 200 status. Page names are wrapped
// in layout.html; fragment names (HTMX) are rendered on their own.
func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.templates.execute(&buf, name, data); err != nil {
		s.logger.Error("template render failed", "name", name, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// renderPartial is for HTMX fragments.
func (s *Server) renderPartial(w http.ResponseWriter, name string, data any) {
	s.render(w, http.StatusOK, name, data)
}

// renderError renders error.html inside the normal layout. It has no request,
// so the layout's session block is skipped (see layout.html).
func (s *Server) renderError(w http.ResponseWriter, status int, msg string) {
	s.render(w, status, "error.html", pageData{
		Title:   fmt.Sprintf("Error %d", status),
		Version: version.String(),
		Data: map[string]any{
			"Status":  status,
			"Message": msg,
		},
	})
}

// pageData is the common envelope every page template receives.
type pageData struct {
	Title     string
	Version   string // build version, shown in the sidebar footer
	Session   *auth.Session
	ActiveNav string
	Flash     string
	CSRFToken string // NEW
	Data      any
}

func (s *Server) newPageData(w http.ResponseWriter, r *http.Request, title, nav string, data any) pageData {
	token, _ := s.csrf.Issue(w)
	return pageData{
		Title:     title,
		Version:   version.String(),
		Session:   auth.SessionFromContext(r.Context()),
		ActiveNav: nav,
		CSRFToken: token,
		Data:      data,
	}
}
