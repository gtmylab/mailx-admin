package server

import (
	"net"
	"net/http"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/config"
)

// serverSettings is the form/view model for the Server configuration page.
type serverSettings struct {
	Hostname   string
	Resolver   string
	MailHost   string
	ListenAddr string
	BaseURL    string
}

func (s *Server) handleServerSettingsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, 200, "server_settings.html", s.newPageData(w, r, "Server", "server", map[string]any{
		"Settings": s.serverSettingsView(),
	}))
}

func (s *Server) serverSettingsView() serverSettings {
	return serverSettings{
		Hostname:   s.cfg.Server.Hostname,
		Resolver:   s.cfg.DNS.Resolver,
		MailHost:   s.cfg.Roundcube.MailHost,
		ListenAddr: s.cfg.Server.ListenAddr,
		BaseURL:    s.cfg.Server.BaseURL,
	}
}

// handleServerSettingsSave persists hostname, DNS resolver and webmail mail host
// to admin.toml. A hostname change also updates the reconciler and queues a sync
// so myhostname/HELO/trusted hosts are re-rendered without a restart.
func (s *Server) handleServerSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form data")
		return
	}

	hostname := strings.TrimSpace(r.FormValue("hostname"))
	resolver := strings.TrimSpace(r.FormValue("resolver"))
	mailHost := strings.TrimSpace(r.FormValue("mail_host"))

	if hostname == "" {
		s.renderFormError(w, "Hostname is required")
		return
	}
	if resolver != "" && !validResolver(resolver) {
		s.renderFormError(w, "DNS resolver must look like 1.1.1.1:53")
		return
	}

	oldHostname := s.cfg.Server.Hostname

	s.cfg.Server.Hostname = hostname
	s.cfg.DNS.Resolver = resolver
	s.cfg.Roundcube.MailHost = mailHost

	if err := config.Save(s.configPath, s.cfg); err != nil {
		s.renderFormError(w, "Failed to save config: "+err.Error())
		return
	}

	hostnameChanged := hostname != oldHostname
	if hostnameChanged {
		// The reconciler holds its own copy of the hostname; update it and queue
		// a sync so the change reaches the daemons in the background.
		if s.rec != nil {
			s.rec.SetHostname(hostname)
		}
		if s.syncer != nil {
			s.syncer.Request("system:config")
		}
	}

	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: s.actorName(r), Action: "system.config", TargetType: "config", TargetID: "admin.toml",
		Result: "ok", Detail: map[string]any{
			"hostname": hostname, "resolver": resolver, "mail_host": mailHost,
			"hostname_changed": hostnameChanged,
		}, RemoteIP: clientIP(r),
	})

	s.renderPartial(w, "server_settings_result", map[string]any{
		"HostnameChanged": hostnameChanged,
	})
}

func validResolver(s string) bool {
	_, _, err := net.SplitHostPort(s)
	return err == nil
}
