package server

import (
	"encoding/json"
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
		"Test Send", "testsend", nil))
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
		"Result": res,
		"Opts":   opts,
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
