package server

import (
	"context"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/execx"
	"github.com/gtmylab/mailx-admin/internal/ssl"
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

	cert := "/etc/letsencrypt/live/" + newHostname + "/fullchain.pem"
	key := "/etc/letsencrypt/live/" + newHostname + "/privkey.pem"

	// Try Let's Encrypt (webroot, then standalone). If the hostname has no A
	// record yet, both fail and we fall back to a self-signed certificate so
	// the services still have a usable cert.
	issued := false
	webroot := []string{"certonly", "--non-interactive", "--agree-tos", "--webroot", "-w", "/var/www/html", "-d", newHostname, "-m", email}
	if _, err := execx.Output(ctx, 2*time.Minute, "certbot", webroot...); err == nil {
		issued = true
	} else if _, err := execx.Output(ctx, 2*time.Minute, "certbot",
		"certonly", "--standalone", "--non-interactive", "--agree-tos", "-d", newHostname, "-m", email); err == nil {
		issued = true
	}

	if !issued {
		fc, k, err := ssl.GenerateSelfSigned(ctx, "/etc/ssl/mailx/"+newHostname, newHostname, []string{newHostname})
		if err != nil {
			s.logger.Warn("self-signed fallback failed", "host", newHostname, "err", err)
			return
		}
		cert, key = fc, k
		s.logger.Info("issued self-signed certificate (no A record for hostname)", "host", newHostname)
	}

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
	return []servicePort{
		{Name: "SMTP", Port: "25", Purpose: "Inbound mail"},
		{Name: "Submission", Port: s.submissionPort(ctx), Purpose: "Authenticated sending (STARTTLS)"},
		{Name: "SMTPS", Port: "465", Purpose: "Authenticated sending (implicit TLS)"},
		{Name: "IMAP", Port: "143", Purpose: "Mailbox retrieval"},
		{Name: "IMAPS", Port: "993", Purpose: "Mailbox retrieval (TLS)"},
		{Name: "POP3", Port: "110", Purpose: "Legacy retrieval"},
		{Name: "POP3S", Port: "995", Purpose: "Legacy retrieval (TLS)"},
	}
}

// submissionPort reads the current submission (587) listener from master.cf. It
// returns the numeric port whether the service is still named "submission" or
// was rewritten to a custom port (the page keeps syslog_name=postfix/submission
// as a marker).
func (s *Server) submissionPort(ctx context.Context) string {
	const awk = `{ if ($1 == "submission" || $1 ~ /^[0-9]+$/) { name=$1 } if ($0 ~ /syslog_name=postfix\/submission/) { print name; exit } }`
	out, err := execx.Output(ctx, systemCmdTimeout, "awk", awk, "/etc/postfix/master.cf")
	if err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			if v == "submission" {
				return "587"
			}
			return v
		}
	}
	return "587"
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
