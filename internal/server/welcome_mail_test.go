package server

import (
	"strings"
	"testing"
)

func TestBuildWelcomeEmail(t *testing.T) {
	msg := buildWelcomeEmail("alice@example.com", "alice", "https://mail.example.com:8080", "example.com")
	s := string(msg)

	for _, want := range []string{
		"From: MailX Email System <admin@example.com>",
		"To: alice@example.com",
		"Subject: Welcome to MailX Email System",
		"Content-Type: multipart/alternative",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Type: text/html; charset=UTF-8",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("message missing %q", want)
		}
	}

	plain := buildWelcomeEmailPlain("alice", "alice@example.com", "https://mail.example.com:8080")
	for _, want := range []string{"alice", "alice@example.com", "https://mail.example.com:8080"} {
		if !strings.Contains(plain, want) {
			t.Errorf("plain part missing %q:\n%s", want, plain)
		}
	}

	html := buildWelcomeEmailHTML("alice", "alice@example.com", "https://mail.example.com:8080")
	for _, want := range []string{"alice@example.com", "https://mail.example.com:8080", "Open Webmail"} {
		if !strings.Contains(html, want) {
			t.Errorf("html part missing %q", want)
		}
	}
}
