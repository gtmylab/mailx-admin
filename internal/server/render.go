package server

import (
	"bytes"
	"context"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/update"
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
	// Every page embeds a CSRF token, so it must never be reused from a cache:
	// a replayed form (back button, bfcache restore, shared URL) would post the
	// token of an earlier render instead of the live cookie.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// renderPartial is for HTMX fragments.
func (s *Server) renderPartial(w http.ResponseWriter, name string, data any) {
	s.render(w, http.StatusOK, name, data)
}

// renderError renders error.html inside the normal layout. It has no request,
// so the layout's session block is skipped and no CSRF token can be read from
// the cookie for it (see layout.html): the layout's script fills the empty
// "Sign out" field from the live cookie in the browser instead.
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
	CSRFToken string // value of the mailx_csrf cookie, embedded for forms and hx-headers
	Data      any

	// Sync is the state of the last configuration sync, for the banner that
	// every page shows while the panel and the server disagree. It is nil on
	// pages rendered without a request (error.html) and when the history is
	// unreadable, and the banner hides itself in that case.
	Sync *syncView

	// Update is the cached release check, shown by the update banner on every
	// page and by the Updates page. Nil while the panel has not checked yet.
	Update *update.Status
}

// newPageData builds the envelope for a full page render, including the CSRF
// token. Every handler that renders a *.html page has to use it: a page whose
// token is empty (because a handler built pageData by hand) leaves hx-headers
// and the layout's "Sign out" form posting nothing, which the CSRF middleware
// answers with 403 "csrf token missing" - the whole page becomes read-only.
//
// Ensure (not Issue) is deliberate: it keeps the token the browser already has,
// so loading one page never invalidates the forms of the pages next to it.
func (s *Server) newPageData(w http.ResponseWriter, r *http.Request, title, nav string, data any) pageData {
	token, err := s.csrf.Ensure(w, r)
	if err != nil {
		// Rendering continues on purpose: a page without a token is still
		// readable, and the request that needs the token will be rejected
		// loudly by the middleware instead of the page failing to render.
		s.logger.Error("ensure csrf token", "err", err)
	}
	return pageData{
		Title:     title,
		Version:   version.String(),
		Session:   auth.SessionFromContext(r.Context()),
		ActiveNav: nav,
		CSRFToken: token,
		Data:      data,
		// Read from the syncer's short-lived cache, so a page render costs at
		// most one row every couple of seconds.
		Sync:   s.syncStatus(r.Context()),
		Update: s.updateStatus(),
	}
}

// syncStatus is nil-safe: a page rendered by a Server without a syncer (tests,
// and any future headless use) still has to render, just without the banner.
func (s *Server) syncStatus(ctx context.Context) *syncView {
	if s.syncer == nil {
		return nil
	}
	return newSyncView(s.syncer.Status(ctx))
}
