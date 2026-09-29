package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/audit"
	"github.com/gtmylab/mailx-admin/internal/auth"
	"github.com/gtmylab/mailx-admin/internal/smtp"
)

func (s *Server) handleTestSendPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, 200, "testsend.html", s.newPageData(w, r,
		"Test Send", "testsend", s.testSendDefaults(r.Context())))
}

// testSendForm is what testsend.html renders with. The page used to hardcode
// 127.0.0.1, an empty From and an empty To, so every first attempt failed on
// input rather than on the mail server.
type testSendForm struct {
	Host    string
	Port    int
	Ports   []int
	TLSMode string
	From    string
	To      string
	Subject string
	Body    string
}

func (s *Server) testSendDefaults(ctx context.Context) testSendForm {
	form := testSendForm{
		Host:    s.cfg.Server.Hostname,
		Port:    587,
		Ports:   []int{587, 465, 25},
		TLSMode: "starttls",
		Subject: "MailX test message",
	}
	if strings.TrimSpace(form.Host) == "" {
		form.Host = "127.0.0.1"
	}
	form.Body = fmt.Sprintf(
		"This is a test message from MailX Admin.\n\nSent %s by %s.",
		time.Now().Format(time.RFC3339), s.cfg.Server.Hostname)

	// Prefill the sender with a real address on this server (postmaster@ on the
	// primary domain) so the relay accepts it instead of refusing an empty one.
	if snap, err := s.store.Snapshot(ctx); err == nil {
		if d := snap.PrimaryDomain(); d != nil {
			form.From = "postmaster@" + d.Name
		}
	}
	if form.From == "" {
		form.From = "postmaster@" + form.Host
	}
	return form
}

// friendlySMTPError turns a raw client error into something an operator can act
// on. The full transcript stays available underneath for the exact bytes.
func friendlySMTPError(errMsg string, opts smtp.SendOptions) string {
	if errMsg == "" {
		return ""
	}
	m := strings.ToLower(errMsg)
	switch {
	case strings.Contains(m, "connection refused"):
		return fmt.Sprintf("Nothing is answering on %s:%d. Check that the mail server is running and that this port is enabled on the Ports page.",
			opts.Host, opts.Port)
	case strings.Contains(m, "no such host"), strings.Contains(m, "no route to host"),
		strings.Contains(m, "network is unreachable"):
		return fmt.Sprintf("%q could not be resolved or reached from this server.", opts.Host)
	case strings.Contains(m, "timeout"), strings.Contains(m, "timed out"), strings.Contains(m, "deadline exceeded"):
		return fmt.Sprintf("Timed out talking to %s:%d. A firewall may be dropping the connection; ports 25, 465 and 587 are commonly filtered.",
			opts.Host, opts.Port)
	case strings.Contains(m, "x509"), strings.Contains(m, "certificate"), strings.Contains(m, "tls:"):
		return "The TLS handshake failed: the certificate is not trusted for this host name. Fix the certificate, or tick “Skip certificate verification” to confirm the problem is only validation."
	case strings.Contains(m, "535"), strings.Contains(m, "auth"):
		return "The server rejected the credentials. Check that the username is the full address and that the password is current."
	case strings.Contains(m, "550"), strings.Contains(m, "554"), strings.Contains(m, "relay"):
		return "The server refused to relay the message. The From or To address may be outside the domains this server accepts mail for."
	case strings.Contains(m, "eof"), strings.Contains(m, "connection reset"):
		return "The server closed the connection during the conversation. If this port speaks implicit TLS, switch the TLS mode to “Implicit (SMTPS)”."
	}
	return ""
}

func (s *Server) handleTestSendRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderFormError(w, "Invalid form")
		return
	}

	port, _ := strconv.Atoi(r.FormValue("port"))
	if port == 0 {
		port = 587
	}

	opts := smtp.SendOptions{
		Host:       r.FormValue("host"),
		Port:       port,
		TLSMode:    smtp.TLSMode(r.FormValue("tls_mode")),
		SkipVerify: r.FormValue("skip_verify") == "on",
		Username:   r.FormValue("username"),
		Password:   r.FormValue("password"),
		From:       r.FormValue("from"),
		To:         r.FormValue("to"),
		Subject:    r.FormValue("subject"),
		Body:       r.FormValue("body"),
		Timeout:    30 * time.Second,
	}

	if opts.Host == "" {
		// The form always posts a host, but a request without one should still
		// try this server before falling back to the loopback address.
		opts.Host = s.cfg.Server.Hostname
	}
	if opts.Host == "" {
		opts.Host = "127.0.0.1"
	}
	if opts.TLSMode == "" {
		opts.TLSMode = smtp.TLSStartTLS
	}

	ctx := r.Context()
	res := smtp.Send(ctx, opts)

	// Persist to test_sends for history
	session := auth.SessionFromContext(ctx)
	transcriptJSON, _ := json.Marshal(res.Transcript)
	successInt := 0
	if res.Success {
		successInt = 1
	}
	_, _ = s.db.ExecContext(ctx, `
        INSERT INTO test_sends
          (admin_user_id, from_addr, to_addr, subject, smtp_host, smtp_port, tls_mode,
           auth_used, success, duration_ms, transcript, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, session.AdminUserID, opts.From, opts.To, opts.Subject,
		opts.Host, opts.Port, string(opts.TLSMode),
		boolInt(opts.Username != ""), successInt,
		res.Duration.Milliseconds(), string(transcriptJSON), res.Error)

	s.auditor.Log(ctx, audit.Entry{
		Actor:      "admin:" + session.Username,
		Action:     "test.send",
		TargetType: "smtp",
		TargetID:   opts.To,
		Result:     ifStr(res.Success, "ok", "error"),
		Detail: map[string]any{
			"host":    opts.Host,
			"port":    opts.Port,
			"success": res.Success,
			"error":   res.Error,
		},
		RemoteIP: clientIP(r),
	})

	s.renderPartial(w, "testsend_result", map[string]any{
		"Result":   res,
		"Opts":     opts,
		"Friendly": friendlySMTPError(res.Error, opts),
	})
}

func (s *Server) handleTestSendHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(), `
        SELECT id, from_addr, to_addr, subject, smtp_host, smtp_port, tls_mode,
               auth_used, success, duration_ms, COALESCE(error, ''), created_at
        FROM test_sends ORDER BY created_at DESC LIMIT 50
    `)
	if err != nil {
		s.renderError(w, 500, "Failed to load history")
		return
	}
	defer rows.Close()

	type row struct {
		ID       int64
		From     string
		To       string
		Subject  string
		Host     string
		Port     int
		TLSMode  string
		AuthUsed bool
		Success  bool
		Duration int64
		Error    string
		Created  time.Time
	}

	var out []row
	for rows.Next() {
		var rr row
		var authUsed, success int
		if err := rows.Scan(&rr.ID, &rr.From, &rr.To, &rr.Subject, &rr.Host, &rr.Port,
			&rr.TLSMode, &authUsed, &success, &rr.Duration, &rr.Error, &rr.Created); err != nil {
			continue
		}
		rr.AuthUsed = authUsed == 1
		rr.Success = success == 1
		out = append(out, rr)
	}

	s.renderPartial(w, "testsend_history", map[string]any{"Rows": out})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func ifStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

var _ = strings.TrimSpace
