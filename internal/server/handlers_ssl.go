package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/ssl"
)

const letsencryptDir = "/etc/letsencrypt"

func (s *Server) handleSSLPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Load all certbot certs
	certs, err := s.listCerts(ctx)
	if err != nil {
		s.renderError(w, 500, "Failed to list certificates: "+err.Error())
		return
	}

	// Notification settings
	var adminEmail, warnDays, lastWarn, lastFail string
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'ssl_admin_email'`).Scan(&adminEmail)
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'ssl_warn_days'`).Scan(&warnDays)
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'ssl_last_notified_warning'`).Scan(&lastWarn)
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'ssl_last_notified_failure'`).Scan(&lastFail)

	// Cron/timer status
	timerEnabled := checkSystemdUnit("certbot.timer")
	cronPresent := checkCrontab("ssl_renewal")

	s.render(w, 200, "ssl.html", s.newPageData(w, r, "SSL Certificates", "ssl",
		map[string]any{
			"Certs":        certs,
			"AdminEmail":   adminEmail,
			"WarnDays":     warnDays,
			"LastWarn":     lastWarn,
			"LastFail":     lastFail,
			"TimerEnabled": timerEnabled,
			"CronPresent":  cronPresent,
		},
	))
}

// handleSSLDetails returns a modal fragment with full cert info.
func (s *Server) handleSSLDetails(w http.ResponseWriter, r *http.Request) {
	certName := r.PathValue("name")

	info, err := ssl.Inspect(certName, letsencryptDir)
	if err != nil {
		s.renderError(w, 404, "Certificate not found: "+err.Error())
		return
	}

	s.renderPartial(w, "ssl_details", map[string]any{
		"Cert": info,
	})
}

// handleSSLRenew runs certbot renew.
func (s *Server) handleSSLRenew(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	certName := r.PathValue("name")
	if certName == "all" {
		certName = ""
	}

	req := ssl.RenewRequest{
		DryRun:   r.FormValue("dry_run") == "on",
		Force:    r.FormValue("force") == "on",
		CertName: certName,
	}

	session := auth.SessionFromContext(r.Context())
	res := ssl.Renew(r.Context(), req)

	// If renewal succeeded and it's not a dry run, refresh cached cert info
	if res.Success && !req.DryRun {
		s.refreshCertCache(r.Context(), certName)
	}

	// Audit
	_ = s.auditor.Log(r.Context(), audit.Entry{
		Actor:      "admin:" + session.Username,
		Action:     "ssl.renew",
		TargetType: "cert",
		TargetID:   certName,
		Result:     ifStr(res.Success, "ok", "error"),
		Detail: map[string]any{
			"dry_run": req.DryRun,
			"force":   req.Force,
			"output":  res.Output,
			"error":   res.Error,
		},
		RemoteIP: clientIP(r),
	})

	// On failure, notify admin email
	if !res.Success && !req.DryRun {
		go s.notifySSLFailure(context.Background(), certName, res.Error)
	}

	s.renderPartial(w, "ssl_renew_result", map[string]any{
		"Result":   res,
		"CertName": certName,
	})
}

// handleSSLSettings saves notification preferences.
func (s *Server) handleSSLSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	adminEmail := strings.TrimSpace(r.FormValue("admin_email"))
	warnDaysStr := strings.TrimSpace(r.FormValue("warn_days"))
	if warnDaysStr == "" {
		warnDaysStr = "14"
	}

	warnDays, err := strconv.Atoi(warnDaysStr)
	if err != nil || warnDays < 1 || warnDays > 89 {
		s.renderFormError(w, "Warning threshold must be between 1 and 89 days")
		return
	}

	ctx := r.Context()
	upsertSetting(ctx, s.db, "ssl_admin_email", adminEmail)
	upsertSetting(ctx, s.db, "ssl_warn_days", strconv.Itoa(warnDays))

	// Install / update the wrapper script + cron entry
	if err := s.installRenewalWrapper(ctx, adminEmail, warnDays); err != nil {
		s.renderFormError(w, "Failed to install renewal wrapper: "+err.Error())
		return
	}

	session := auth.SessionFromContext(ctx)
	_ = s.auditor.Log(ctx, audit.Entry{
		Actor:      "admin:" + session.Username,
		Action:     "ssl.settings",
		TargetType: "settings",
		Result:     "ok",
		Detail: map[string]any{
			"admin_email": adminEmail,
			"warn_days":   warnDays,
		},
		RemoteIP: clientIP(r),
	})

	w.Header().Set("HX-Redirect", "/ssl?flash="+encodeFlash("SSL notification settings saved"))
	w.WriteHeader(http.StatusOK)
}

// handleSSLSendTest sends a test notification.
func (s *Server) handleSSLSendTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var adminEmail string
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'ssl_admin_email'`).Scan(&adminEmail)
	if adminEmail == "" {
		s.renderFormError(w, "No admin email configured")
		return
	}

	// Build a fake cert for the email
	certName := ""
	var primaryDomain string
	_ = s.db.QueryRowContext(ctx, `SELECT name FROM domains WHERE is_primary = 1 LIMIT 1`).Scan(&primaryDomain)
	if primaryDomain == "" {
		_ = s.db.QueryRowContext(ctx, `SELECT name FROM domains LIMIT 1`).Scan(&primaryDomain)
	}
	certName = primaryDomain

	cert, _ := ssl.Inspect(certName, letsencryptDir)
	nc := ssl.NotifyContext{
		Hostname: s.cfg.Server.Hostname,
		Domain:   certName,
		Cert:     cert,
		Reason:   "TEST notification from MailX Admin at " + time.Now().Format(time.RFC3339),
	}

	subject, body := ssl.RenderFailureEmail(nc)
	subject = "[TEST] " + subject

	if err := s.sendMail(ctx, adminEmail, subject, body); err != nil {
		s.renderFormError(w, "Send failed: "+err.Error())
		return
	}

	s.renderPartial(w, "ssl_settings_saved", map[string]any{
		"Message": "Test notification sent to " + adminEmail,
	})
}

// ---- helpers ----

func (s *Server) listCerts(ctx context.Context) ([]*ssl.CertInfo, error) {
	// Run `certbot certificates` and parse
	out, err := exec.CommandContext(ctx, "certbot", "certificates").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("certbot certificates: %w: %s", err, out)
	}

	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Certificate Name:") {
			name := strings.TrimSpace(strings.TrimPrefix(line, "Certificate Name:"))
			names = append(names, name)
		}
	}

	var certs []*ssl.CertInfo
	for _, name := range names {
		info, err := ssl.Inspect(name, letsencryptDir)
		if err != nil {
			s.logger.Warn("inspect cert", "name", name, "err", err)
			continue
		}
		certs = append(certs, info)
	}
	return certs, nil
}

func (s *Server) refreshCertCache(ctx context.Context, certName string) {
	// No-op for now — we always inspect on demand. Reserved for future
	// caching into the ssl_certs table.
	_ = ctx
	_ = certName
}

// notifySSLFailure sends the admin email on renewal failure.
func (s *Server) notifySSLFailure(ctx context.Context, certName, reason string) {
	var adminEmail string
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'ssl_admin_email'`).Scan(&adminEmail)
	if adminEmail == "" {
		return
	}

	cert, _ := ssl.Inspect(certName, letsencryptDir)
	nc := ssl.NotifyContext{
		Hostname: s.cfg.Server.Hostname,
		Domain:   certName,
		Cert:     cert,
		Reason:   reason,
	}
	subject, body := ssl.RenderFailureEmail(nc)

	if err := s.sendMail(ctx, adminEmail, subject, body); err != nil {
		s.logger.Warn("ssl failure email", "err", err)
		return
	}
	// Mark notified
	upsertSetting(ctx, s.db, "ssl_last_notified_failure", time.Now().Format(time.RFC3339))
}

func (s *Server) sendMail(ctx context.Context, to, subject, body string) error {
	// Reuse the same helper the password email uses
	var fromDomain string
	_ = s.db.QueryRowContext(ctx, `SELECT name FROM domains WHERE is_primary = 1 LIMIT 1`).Scan(&fromDomain)
	if fromDomain == "" {
		fromDomain = "localhost"
	}

	msg := buildRFC822("admin@"+fromDomain, to, subject, body)
	return smtpSendLocal(ctx, "admin@"+fromDomain, to, msg)
}

func checkSystemdUnit(name string) bool {
	out, _ := exec.Command("systemctl", "is-enabled", name).Output()
	return strings.TrimSpace(string(out)) == "enabled"
}

func checkCrontab(pattern string) bool {
	out, _ := exec.Command("crontab", "-l").Output()
	return strings.Contains(string(out), pattern)
}

func upsertSetting(ctx context.Context, db *sql.DB, key, value string) {
	_, _ = db.ExecContext(ctx, `
        INSERT INTO settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
    `, key, value)
}
