package server

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"github.com/gtmylab/mailx-admin/internal/models"
	"net/smtp"
	"strings"
)

// sendPasswordEmail sends the generated password to an alternate address.
// Optional — only called if the admin entered one.
//
// We send via localhost:25 (Postfix) with no auth, which is standard for
// a mail server sending mail for itself.
func (s *Server) sendPasswordEmail(ctx context.Context, userID int64, password, to string) error {
	if to == "" {
		return nil
	}

	// Look up user
	var user models.User
	var active int
	var lastLogin sql.NullTime

	err := s.db.QueryRowContext(ctx, `
        SELECT id, domain_id, username, email, password_hash, quota_mb, active, is_admin, last_login, created_at, updated_at
        FROM users WHERE id = ?
    `, userID).Scan(
		&user.ID, &user.DomainID, &user.Username, &user.Email, &user.PasswordHash,
		&user.QuotaMB, &active, &user.IsAdmin, &lastLogin,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("load user: %w", err)
	}

	// Get primary domain for From address
	fromDomain := s.primaryDomain(ctx)

	subject := "Your email password for " + user.Email
	body := buildPasswordEmail(user.Email, password, fromDomain)

	msg := bytes.NewBuffer(nil)
	fmt.Fprintf(msg, "From: MailX Admin <admin@%s>\r\n", fromDomain)
	fmt.Fprintf(msg, "To: %s\r\n", to)
	fmt.Fprintf(msg, "Subject: %s\r\n", subject)
	fmt.Fprintf(msg, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(msg, "Content-Type: text/plain; charset=UTF-8\r\n")
	fmt.Fprintf(msg, "\r\n")
	msg.WriteString(body)

	// Send via localhost Postfix (no auth)
	return smtp.SendMail("127.0.0.1:25", nil, "admin@"+fromDomain, []string{to}, msg.Bytes())
}

func buildPasswordEmail(email, password, domain string) string {
	var b strings.Builder
	b.WriteString("Hello,\r\n\r\n")
	fmt.Fprintf(&b, "An email account has been created or updated for you.\r\n\r\n")
	fmt.Fprintf(&b, "Email address: %s\r\n", email)
	fmt.Fprintf(&b, "Password:      %s\r\n", password)
	fmt.Fprintf(&b, "\r\n")
	fmt.Fprintf(&b, "You can log in to webmail at:\r\n")
	fmt.Fprintf(&b, "  https://%s:8080\r\n", domain)
	fmt.Fprintf(&b, "\r\n")
	fmt.Fprintf(&b, "Please change your password after first login.\r\n\r\n")
	fmt.Fprintf(&b, "— MailX Admin\r\n")
	return b.String()
}
