package reconciler

import (
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

func TestRenderSenderTransport(t *testing.T) {
	ips := []models.OutboundIP{
		{ID: 2, IP: "5.6.7.8", Mode: models.IPModeRules, Active: true, Rules: []models.OutboundRule{
			{MatchType: models.RuleMatchDomain, MatchValue: "example.com"},
			{MatchType: models.RuleMatchEmail, MatchValue: "alice@example.com"},
			{MatchType: models.RuleMatchUser, MatchValue: "bob"},
		}},
		// disabled and always IPs must not produce sender_transport lines
		{ID: 1, IP: "1.2.3.4", Mode: models.IPModeAlways, Active: true},
		{ID: 3, IP: "9.9.9.9", Mode: models.IPModeRules, Active: false},
	}

	out := string(RenderSenderTransport(ips))
	for _, want := range []string{
		"@example.com\tsmtpip2",
		"alice@example.com\tsmtpip2",
		"bob@\tsmtpip2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sender_transport missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "smtpip1") || strings.Contains(out, "smtpip3") {
		t.Errorf("sender_transport included a non-rules IP:\n%s", out)
	}
}

func TestRenderOutboundTransports(t *testing.T) {
	ips := []models.OutboundIP{
		{ID: 1, IP: "1.2.3.4", Mode: models.IPModeAlways, Active: true},
		{ID: 2, IP: "5.6.7.8", Mode: models.IPModeRules, Active: true},
		{ID: 3, IP: "9.9.9.9", Mode: models.IPModeDisabled, Active: true},
	}

	out := string(RenderOutboundTransports(ips))
	if !strings.Contains(out, "smtpip1 unix - - n - - smtp\n  -o smtp_bind_address=1.2.3.4") {
		t.Errorf("missing smtpip1 stanza:\n%s", out)
	}
	if !strings.Contains(out, "smtpip2 unix - - n - - smtp\n  -o smtp_bind_address=5.6.7.8") {
		t.Errorf("missing smtpip2 stanza:\n%s", out)
	}
	if strings.Contains(out, "smtpip3") {
		t.Errorf("disabled IP got a transport:\n%s", out)
	}
}

func TestDefaultOutboundTransport(t *testing.T) {
	ips := []models.OutboundIP{
		{ID: 1, IP: "1.2.3.4", Mode: models.IPModeAlways, Active: true, Priority: 1},
		{ID: 2, IP: "5.6.7.8", Mode: models.IPModeAlways, Active: true, Priority: 9},
	}
	if got := DefaultOutboundTransport(ips); got != "smtpip2" {
		t.Errorf("default transport = %q, want smtpip2 (highest priority)", got)
	}

	if got := DefaultOutboundTransport(nil); got != "smtp" {
		t.Errorf("default transport with no IPs = %q, want smtp", got)
	}
}

func TestRenderSuppressions(t *testing.T) {
	sups := []models.Suppression{
		{Email: "spam@example.com"},
		{Email: "old@example.net"},
	}
	out := string(RenderSuppressions(sups))
	if !strings.Contains(out, "spam@example.com\t550 5.7.1 recipient suppressed by policy") {
		t.Errorf("missing suppression line:\n%s", out)
	}
}
