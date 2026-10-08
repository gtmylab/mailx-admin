package logs

import (
	"testing"
	"time"
)

// TestParseDovecotLoginIPv6 — the real log line logs rip=/lip= as IPv6
// loopback (::1), which the old rip=([\d.]+) pattern could not match, so the
// Dovecot login was silently dropped and users.last_login never updated.
func TestParseDovecotLoginIPv6(t *testing.T) {
	line := "Oct  8 19:23:57 mx419 dovecot: imap-login: Login: user=<lets.help@mymashalat.com>, method=PLAIN, rip=::1, lip=::1, mpid=118758, secured, session=<B+hYLFldMrI>"
	ev := ParseLine(line, time.Now())
	if ev == nil {
		t.Fatalf("dovecot login line was not parsed")
	}
	if ev.Action != "login" {
		t.Errorf("action = %q, want login", ev.Action)
	}
	if ev.FromAddr != "lets.help@mymashalat.com" {
		t.Errorf("from = %q, want lets.help@mymashalat.com", ev.FromAddr)
	}
	if ev.Domain != "mymashalat.com" {
		t.Errorf("domain = %q, want mymashalat.com", ev.Domain)
	}
}

// TestParsePostfixRelayWithPort — a real outbound delivery line carries
// relay=<host>[<ip>]:<port>. The old relay=(\S+?)(?:\[\d+\])? pattern stopped
// before status=, so status came out empty and "Sent" traffic never counted.
func TestParsePostfixRelayWithPort(t *testing.T) {
	line := "Oct  8 07:36:52 mx419 postfix/smtp[12345]: 3F1A2B: to=<someone@gmail.com>, relay=gmail-smtp-in.l.google.com[142.250.150.27]:25, delay=1.2, delays=0.01/0/0.5/0.7, dsn=2.0.0, status=sent (250 2.0.0 OK)"
	ev := ParseLine(line, time.Now())
	if ev == nil {
		t.Fatalf("postfix delivery line was not parsed")
	}
	if ev.Action != "delivery" {
		t.Errorf("action = %q, want delivery", ev.Action)
	}
	if ev.Status != "sent" {
		t.Errorf("status = %q, want sent", ev.Status)
	}
	if ev.ToAddr != "someone@gmail.com" {
		t.Errorf("to = %q, want someone@gmail.com", ev.ToAddr)
	}
	if ev.Domain != "gmail.com" {
		t.Errorf("domain = %q, want gmail.com", ev.Domain)
	}
	if ev.Relay != "gmail-smtp-in.l.google.com[142.250.150.27]:25" {
		t.Errorf("relay = %q, want full relay including [ip]:port", ev.Relay)
	}
}
