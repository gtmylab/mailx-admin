package server

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"mime/multipart"
	"net/textproto"
	"strings"
	"time"
)

// sendWelcomeEmailAfterSync sends the welcome mail once the queued config sync
// has rendered the new mailbox, so Postfix does not bounce it as "unknown user"
// before the vmailbox entry exists. It runs off the request path and is
// best-effort.
func (s *Server) sendWelcomeEmailAfterSync(email string) {
	// A short fixed delay is used instead of polling the syncer: its queue and
	// running flag are not updated atomically, so a poller can observe "idle" in
	// the instant between draining the queue and marking the run as running and
	// send too early. The reconcile finishes well within this window.
	time.Sleep(15 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.sendWelcomeEmail(ctx, email)
}

// sendWelcomeEmail sends a welcome message to a newly-created mailbox. It is the
// panel's counterpart to the installer's welcome mail, and is best-effort: a mail
// that cannot be sent must not undo the account it announces.
func (s *Server) sendWelcomeEmail(ctx context.Context, email string) {
	username, _, _ := strings.Cut(email, "@")
	fromDomain := s.primaryDomain(ctx)
	webmailURL := "https://" + s.cfg.Server.Hostname + ":8080"

	msg := buildWelcomeEmail(email, username, webmailURL, fromDomain)
	// The envelope sender must be a bare address; the display name lives only in
	// the From: header built by buildWelcomeEmail.
	if err := smtpSendLocal(ctx, "admin@"+fromDomain, email, msg); err != nil {
		s.logger.Warn("welcome email failed", "email", email, "err", err)
	}
}

// primaryDomain returns the domain the panel sends its own mail from, falling
// back to localhost when none is marked primary.
func (s *Server) primaryDomain(ctx context.Context) string {
	var name string
	_ = s.db.QueryRowContext(ctx, `SELECT name FROM domains WHERE is_primary = 1 LIMIT 1`).Scan(&name)
	if name == "" {
		return "localhost"
	}
	return name
}

// buildWelcomeEmail assembles a multipart/alternative welcome message (plain text
// and HTML), so it renders nicely in both kinds of client.
func buildWelcomeEmail(email, username, webmailURL, fromDomain string) []byte {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	fmt.Fprintf(&buf, "From: MailX Email System <admin@%s>\r\n", fromDomain)
	fmt.Fprintf(&buf, "To: %s\r\n", email)
	fmt.Fprintf(&buf, "Subject: Welcome to MailX Email System\r\n")
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: multipart/alternative; boundary=%q\r\n", w.Boundary())
	fmt.Fprintf(&buf, "\r\n")

	p, _ := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=UTF-8"}})
	fmt.Fprintf(p, "%s\r\n", buildWelcomeEmailPlain(username, email, webmailURL))

	h, _ := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/html; charset=UTF-8"}})
	fmt.Fprintf(h, "%s\r\n", buildWelcomeEmailHTML(username, email, webmailURL))

	_ = w.Close()
	return buf.Bytes()
}

func buildWelcomeEmailPlain(username, email, webmailURL string) string {
	var b strings.Builder
	b.WriteString("Welcome to MailX Email System\r\n\r\n")
	fmt.Fprintf(&b, "Hello %s,\r\n\r\n", username)
	b.WriteString("Your mailbox is ready. Sign in with your full email address.\r\n\r\n")
	fmt.Fprintf(&b, "  Email address: %s\r\n", email)
	fmt.Fprintf(&b, "  Webmail:       %s\r\n\r\n", webmailURL)
	b.WriteString("- MailX Admin Team\r\n")
	return b.String()
}

func buildWelcomeEmailHTML(username, email, webmailURL string) string {
	u := html.EscapeString(username)
	e := html.EscapeString(email)
	url := html.EscapeString(webmailURL)

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f4f5f7;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f5f7;padding:24px 0;">
<tr><td align="center">
<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;background:#ffffff;border:1px solid #e2e4e8;border-radius:8px;overflow:hidden;">
<tr><td style="background:#1a73e8;padding:24px 32px;">
<h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:600;">Welcome to MailX Email System</h1>
</td></tr>
<tr><td style="padding:32px;">
<p style="margin:0 0 16px;color:#1f2328;font-size:15px;line-height:1.6;">Hello `)
	b.WriteString(u)
	b.WriteString(`,</p>
<p style="margin:0 0 16px;color:#1f2328;font-size:15px;line-height:1.6;">Your mailbox is ready. Sign in with your full email address.</p>
<table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 20px;width:100%;background:#f6f8fa;border:1px solid #e2e4e8;border-radius:6px;">
<tr>
<td style="padding:12px 16px;color:#1f2328;font-size:14px;">Email address</td>
<td style="padding:12px 16px;color:#1a73e8;font-size:14px;font-weight:600;">`)
	b.WriteString(e)
	b.WriteString(`</td>
</tr>
</table>
<p style="margin:0 0 24px;"><a href="`)
	b.WriteString(url)
	b.WriteString(`" style="display:inline-block;background:#1a73e8;color:#ffffff;text-decoration:none;font-size:15px;font-weight:600;padding:12px 24px;border-radius:6px;">Open Webmail</a></p>
<p style="margin:0 0 16px;color:#1f2328;font-size:14px;line-height:1.6;">Webmail: <a href="`)
	b.WriteString(url)
	b.WriteString(`" style="color:#1a73e8;">`)
	b.WriteString(url)
	b.WriteString(`</a></p>
<p style="margin:0;color:#6a737d;font-size:13px;line-height:1.6;">- MailX Admin Team</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
`)
	return b.String()
}
