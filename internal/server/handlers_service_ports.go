package server

import (
	"context"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/execx"
)

// sslAdminEmail returns the address certbot uses for registration/expiry
// notices, falling back to the server hostname.
func (s *Server) sslAdminEmail(ctx context.Context) string {
	var email string
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'ssl_admin_email'`).Scan(&email)
	if email == "" {
		email = "admin@" + s.cfg.Server.Hostname
	}
	return email
}

// reissueHostCertificates issues (or renews) a Let's Encrypt certificate for the
// new hostname and repoints Postfix/Dovecot at it. It is best-effort and runs in
// the background: a certbot failure must not roll back the hostname change.
func (s *Server) reissueHostCertificates(ctx context.Context, newHostname string) {
	if newHostname == "" {
		return
	}
	email := s.sslAdminEmail(ctx)

	// Prefer webroot (no service downtime); fall back to standalone.
	webroot := []string{"certonly", "--non-interactive", "--agree-tos", "--webroot", "-w", "/var/www/html", "-d", newHostname, "-m", email}
	if _, err := execx.Output(ctx, 2*time.Minute, "certbot", webroot...); err != nil {
		_, _ = execx.Output(ctx, 2*time.Minute, "certbot",
			"certonly", "--standalone", "--non-interactive", "--agree-tos", "-d", newHostname, "-m", email)
	}

	cert := "/etc/letsencrypt/live/" + newHostname + "/fullchain.pem"
	key := "/etc/letsencrypt/live/" + newHostname + "/privkey.pem"

	_ = execx.Run(ctx, 30*time.Second, "postconf", "-e", "smtpd_tls_cert_file="+cert)
	_ = execx.Run(ctx, 30*time.Second, "postconf", "-e", "smtpd_tls_key_file="+key)
	_ = execx.Run(ctx, 30*time.Second, "systemctl", "reload-or-restart", "postfix", "dovecot")
}

// ---- Service ports ---------------------------------------------------------

type servicePort struct {
	Name    string
	Port    string
	Purpose string
}

// currentServicePorts reports the mail stack's core listening ports, read from
// the live config so the page reflects the running daemons.
func (s *Server) currentServicePorts(ctx context.Context) []servicePort {
	ports := []servicePort{
		{Name: "SMTP", Port: "25", Purpose: "Inbound mail"},
		{Name: "Submission", Port: s.submissionPort(ctx), Purpose: "Authenticated sending (STARTTLS)"},
		{Name: "SMTPS", Port: "465", Purpose: "Authenticated sending (implicit TLS)"},
		{Name: "IMAP", Port: s.dovecotPort(ctx, "imap", "143"), Purpose: "Mailbox retrieval"},
		{Name: "IMAPS", Port: s.dovecotPort(ctx, "imaps", "993"), Purpose: "Mailbox retrieval (TLS)"},
		{Name: "POP3", Port: s.dovecotPort(ctx, "pop3", "110"), Purpose: "Legacy retrieval"},
		{Name: "POP3S", Port: s.dovecotPort(ctx, "pop3s", "995"), Purpose: "Legacy retrieval (TLS)"},
	}
	return ports
}

func (s *Server) submissionPort(ctx context.Context) string {
	out, err := execx.Output(ctx, systemCmdTimeout, "grep", "-E", "^submission\\s+inet", "/etc/postfix/master.cf")
	if err == nil {
		if fields := strings.Fields(string(out)); len(fields) > 0 {
			return fields[0]
		}
	}
	return "587"
}

func (s *Server) dovecotPort(ctx context.Context, proto, fallback string) string {
	out, err := execx.Output(ctx, systemCmdTimeout, "doveconf", "-h", "service", proto, "inet_listener", proto, "port")
	if err == nil && strings.TrimSpace(string(out)) != "" {
		return strings.TrimSpace(string(out))
	}
	return fallback
}

func (s *Server) handleServicePortsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, 200, "service_ports.html", s.newPageData(w, r, "Service ports", "service-ports", map[string]any{
		"Ports": s.currentServicePorts(r.Context()),
	}))
}

// handleServicePortsSave changes the submission port in master.cf, opens the new
// port in the firewall, and reloads Postfix.
func (s *Server) handleServicePortsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}
	newPort := strings.TrimSpace(r.FormValue("submission_port"))
	if newPort == "" {
		s.renderFormError(w, "Submission port is required")
		return
	}
	p, err := strconv.Atoi(newPort)
	if err != nil || p < 1 || p > 65535 {
		s.renderFormError(w, "Invalid port")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), systemCmdTimeout)
	defer cancel()

	// Rewrite the submission service to listen on the new numeric port.
	cmd := exec.CommandContext(ctx, "sed", "-i", "s|^submission inet|"+newPort+" inet|", "/etc/postfix/master.cf")
	if out, err := cmd.CombinedOutput(); err != nil {
		s.renderFormError(w, "Failed to update master.cf: "+string(out))
		return
	}

	// Open the port in the firewall.
	if s.firewallBackend() == "ufw" {
		_, _ = execx.Output(ctx, systemCmdTimeout, "ufw", "allow", newPort+"/tcp")
	} else {
		_, _ = execx.Output(ctx, systemCmdTimeout, "firewall-cmd", "--permanent", "--add-port", newPort+"/tcp")
		_, _ = execx.Output(ctx, systemCmdTimeout, "firewall-cmd", "--reload")
	}

	if out, err := execx.Output(ctx, systemCmdTimeout, "postfix", "reload"); err != nil {
		s.renderFormError(w, "postfix reload failed: "+string(out))
		return
	}

	s.renderPartial(w, "service_ports_result", map[string]any{
		"Message": "Submission port changed to " + newPort + " and Postfix reloaded.",
	})
}
