package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/smtp"
)

// relayView is the outbound smarthost form. Password is deliberately excluded:
// it is write-only, so the form never echoes it back.
type relayView struct {
	Enabled  bool
	Host     string
	Port     int
	Username string
	TLSMode  string
}

func (s *Server) handleRelayPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, 200, "relay.html", s.newPageData(w, r, "Outbound relay", "relay", map[string]any{
		"Relay": s.readRelaySettings(r.Context()),
	}))
}

func (s *Server) handleRelaySave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}

	enabled := r.FormValue("enabled") == "on"
	host := strings.TrimSpace(r.FormValue("host"))
	port, _ := strconv.Atoi(r.FormValue("port"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	tlsMode := r.FormValue("tls")

	if enabled && host == "" {
		s.renderFormError(w, "Relay host is required when relay is enabled")
		return
	}

	values := map[string]string{
		"relay_enabled":  boolStr(enabled),
		"relay_host":     host,
		"relay_port":     strconv.Itoa(port),
		"relay_username": username,
		"relay_tls":      tlsMode,
	}
	for k, v := range values {
		upsertSetting(r.Context(), s.db, k, v)
	}
	// The password is only written when the admin typed a new one, so saving the
	// form without touching the field keeps the stored secret.
	if password != "" {
		upsertSetting(r.Context(), s.db, "relay_password", password)
	}

	s.requestSync("relay.change")
	w.Header().Set("HX-Redirect", "/system/relay?flash="+encodeFlash("Relay settings saved"))
	w.WriteHeader(http.StatusOK)
}

// handleRelayTest attempts a connection (and, when credentials are given, an
// AUTH) to the relay host as entered in the form, without sending any mail. It
// is the "test connection" action next to Save.
func (s *Server) handleRelayTest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}

	host := strings.TrimSpace(r.FormValue("host"))
	port, _ := strconv.Atoi(r.FormValue("port"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	tlsMode := r.FormValue("tls")

	if host == "" {
		s.renderFormError(w, "Relay host is required")
		return
	}
	if port == 0 {
		port = 587
	}

	mode := smtp.TLSNone
	switch tlsMode {
	case "starttls":
		mode = smtp.TLSStartTLS
	case "smtps":
		mode = smtp.TLSImplicit
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	res := smtp.Send(ctx, smtp.SendOptions{
		Host:       host,
		Port:       port,
		TLSMode:    mode,
		Username:   username,
		Password:   password,
		SkipVerify: true,
		ProbeOnly:  true,
	})

	s.renderPartial(w, "relay_test", map[string]any{"Result": res})
}

// readRelaySettings loads the relay form state from the settings table.
func (s *Server) readRelaySettings(ctx context.Context) relayView {
	var enabled, host, portStr, username, tlsMode string
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'relay_enabled'`).Scan(&enabled)
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'relay_host'`).Scan(&host)
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'relay_port'`).Scan(&portStr)
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'relay_username'`).Scan(&username)
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'relay_tls'`).Scan(&tlsMode)

	port, _ := strconv.Atoi(portStr)
	return relayView{
		Enabled:  enabled == "1" || enabled == "true",
		Host:     host,
		Port:     port,
		Username: username,
		TLSMode:  tlsMode,
	}
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
