package server

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/config"
)

// serverSettings is the form/view model for the Server configuration page.
type serverSettings struct {
	Hostname   string
	Resolver   string
	MailHost   string
	Mailname   string // /etc/mailname
	ListenAddr string
	BaseURL    string
}

func (s *Server) handleServerSettingsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, 200, "server_settings.html", s.newPageData(w, r, "Server", "server", map[string]any{
		"Settings":  s.serverSettingsView(),
		"Time":      timeStatusView(r.Context()),
		"Timezones": commonTimezones,
	}))
}

func (s *Server) serverSettingsView() serverSettings {
	mailname := ""
	if b, err := os.ReadFile("/etc/mailname"); err == nil {
		mailname = strings.TrimSpace(string(b))
	}
	return serverSettings{
		Hostname:   s.cfg.Server.Hostname,
		Resolver:   s.cfg.DNS.Resolver,
		MailHost:   s.cfg.Roundcube.MailHost,
		Mailname:   mailname,
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
	mailname := strings.TrimSpace(r.FormValue("mailname"))
	baseURL := strings.TrimSpace(r.FormValue("base_url"))

	if hostname == "" {
		s.renderFormError(w, "Hostname is required")
		return
	}
	if resolver != "" && !validResolver(resolver) {
		s.renderFormError(w, "DNS resolver must look like 1.1.1.1:53")
		return
	}

	oldHostname := s.cfg.Server.Hostname

	// Strict A-record pre-check: a hostname or panel host that does not resolve
	// yet will fail LetsEncrypt, so refuse to change either until DNS is live.
	if hostname != oldHostname && !s.hostnameResolves(r.Context(), hostname) {
		s.renderFormError(w, "Hostname "+hostname+" has no A record yet. Publish the DNS record, then retry.")
		return
	}
	if host := panelHost(baseURL); host != "" && host != panelHost(s.cfg.Server.BaseURL) && !s.hostnameResolves(r.Context(), host) {
		s.renderFormError(w, "Panel host "+host+" has no A record yet. Publish the DNS record, then retry.")
		return
	}

	s.cfg.Server.Hostname = hostname
	s.cfg.DNS.Resolver = resolver
	s.cfg.Roundcube.MailHost = mailHost
	s.cfg.Server.BaseURL = baseURL

	// /etc/mailname is the host the mail stack and DNS records identify as the
	// inbound mail host.
	if mailname != "" {
		_ = os.WriteFile("/etc/mailname", []byte(mailname+"\n"), 0o644)
	}

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
		// Re-issue the Let's Encrypt certificate for the new hostname and repoint
		// the mail services at it, in the background.
		go s.reissueHostCertificates(context.Background(), hostname)
	}

	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor: s.actorName(r), Action: "system.config", TargetType: "config", TargetID: "admin.toml",
		Result: "ok", Detail: map[string]any{
			"hostname": hostname, "resolver": resolver, "mail_host": mailHost,
			"mailname": mailname, "base_url": baseURL, "hostname_changed": hostnameChanged,
		}, RemoteIP: clientIP(r),
	})

	s.renderPartial(w, "server_settings_result", map[string]any{
		"HostnameChanged": hostnameChanged,
	})
}

// panelHost extracts the bare host from a base URL ("https://admin.example.com"
// -> "admin.example.com") for the A-record pre-check.
func panelHost(baseURL string) string {
	h := strings.TrimSpace(baseURL)
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if i := strings.IndexAny(h, "/:"); i >= 0 {
		h = h[:i]
	}
	return strings.TrimSpace(h)
}

// hostnameResolves reports whether hostname resolves to a non-loopback address,
// i.e. a real A record exists in DNS.
func (s *Server) hostnameResolves(ctx context.Context, hostname string) bool {
	if hostname == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, hostname)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && !ip.IsLoopback() {
			return true
		}
	}
	return false
}

func validResolver(s string) bool {
	_, _, err := net.SplitHostPort(s)
	return err == nil
}
