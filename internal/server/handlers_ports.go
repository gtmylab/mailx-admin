package server

import (
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/mutations"
	"github.com/gtmylab/mailx-admin/internal/ports"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func (s *Server) handlePortsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Load from DB
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, port, service, tls_mode, require_sasl, COALESCE(description,''), enabled
        FROM port_listeners ORDER BY port
    `)
	if err != nil {
		s.renderError(w, 500, "Failed to load ports")
		return
	}
	defer rows.Close()

	type row struct {
		ID, Port, RequireSASL, Enabled int64
		Service, TLSMode, Description  string
	}
	var custom []row
	for rows.Next() {
		var p row
		if err := rows.Scan(&p.ID, &p.Port, &p.Service, &p.TLSMode, &p.RequireSASL, &p.Description, &p.Enabled); err != nil {
			continue
		}
		custom = append(custom, p)
	}

	// Parse master.cf to show what's currently listening
	listeners, _, _ := ports.Parse(s.cfg.Mail.PostfixConfDir + "/master.cf")

	// Filter out managed ones from the "system" list
	var systemListeners []ports.Listener
	for _, l := range listeners {
		if !l.Managed {
			systemListeners = append(systemListeners, l)
		}
	}

	s.render(w, 200, "ports.html", s.newPageData(w, r, "Ports", "ports",
		map[string]any{
			"System": systemListeners,
			"Custom": custom,
		},
	))
}

func (s *Server) handlePortNew(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "port_form", map[string]any{})
}

func (s *Server) handlePortCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	port, _ := strconv.Atoi(r.FormValue("port"))

	in := mutations.CreatePortInput{
		Port:        port,
		TLSMode:     r.FormValue("tls_mode"),
		RequireSASL: r.FormValue("require_sasl") == "on",
		Description: strings.TrimSpace(r.FormValue("description")),
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.CreatePort(r.Context(), actor, in); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/ports?flash="+encodeFlash("Port "+strconv.Itoa(port)+" added"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handlePortDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid port ID")
		return
	}

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.DeletePort(r.Context(), actor, id); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/ports?flash="+encodeFlash("Port removed"))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handlePortToggle(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.renderError(w, 400, "Invalid port ID")
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	enabled := r.FormValue("enabled") == "true"

	actor := mutations.Actor{
		Name:     "admin:" + auth.SessionFromContext(r.Context()).Username,
		RemoteIP: clientIP(r),
	}

	if _, err := s.mutations.TogglePort(r.Context(), actor, id, enabled); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	w.Header().Set("HX-Redirect", "/ports?flash="+encodeFlash("Port updated"))
	w.WriteHeader(http.StatusOK)
}

// handlePortPreviewMasterCF shows what master.cf would look like if the
// proposed port were added (used for the "Preview" button).
func (s *Server) handlePortPreview(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	port, _ := strconv.Atoi(r.FormValue("port"))
	candidate := models.PortListener{
		Port:        port,
		Service:     "smtpd",
		TLSMode:     r.FormValue("tls_mode"),
		RequireSASL: r.FormValue("require_sasl") == "on",
		Enabled:     true,
	}

	// Get current listeners
	var current []models.PortListener
	rows, _ := s.db.QueryContext(r.Context(), `
        SELECT id, port, service, tls_mode, require_sasl, COALESCE(description,''), enabled
        FROM port_listeners
    `)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var l models.PortListener
			var sasl, enabled int
			rows.Scan(&l.ID, &l.Port, &l.Service, &l.TLSMode, &sasl, &l.Description, &enabled)
			l.RequireSASL = sasl == 1
			l.Enabled = enabled == 1
			current = append(current, l)
		}
	}

	if err := ports.Validate(candidate, current); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	if err := ports.CheckPortAvailable(port); err != nil {
		s.renderFormError(w, err.Error())
		return
	}

	// Render preview
	preview := ports.Render(mustReadFile(s.cfg.Mail.PostfixConfDir+"/master.cf"), append(current, candidate))

	s.renderPartial(w, "port_preview", map[string]any{
		"MasterCF": string(preview),
	})
}

func mustReadFile(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}
