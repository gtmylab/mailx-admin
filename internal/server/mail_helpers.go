// internal/server/mail_helpers.go

package server

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
	"time"
)

func buildRFC822(from, to, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=UTF-8\r\n")
	fmt.Fprintf(&b, "\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

func smtpSendLocal(ctx context.Context, from, to string, msg []byte) error {
	return smtp.SendMail(
		"127.0.0.1:25",
		nil,
		from,
		[]string{to},
		msg,
	)
}
