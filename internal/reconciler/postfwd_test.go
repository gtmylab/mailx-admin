package reconciler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

func rateLimitSnapshot() *models.Snapshot {
	return &models.Snapshot{
		Domains: []models.Domain{
			{ID: 1, Name: "example.com", IsPrimary: true, Active: true,
				OutboundRateLimit: 500, OutboundRateAction: models.RateActionDefer},
			{ID: 2, Name: "shop.example", Active: true}, // no limit
		},
	}
}

// TestRenderPostfwdConfWritesOneRateRule is the contract with postfwd: a rule
// per limited domain, with the counter key, the window and the reply code that
// make it a *rate* limit rather than a reject-everything.
func TestRenderPostfwdConfWritesOneRateRule(t *testing.T) {
	out := string(RenderPostfwdConf(rateLimitSnapshot().Domains))

	for _, want := range []string{
		"id=RL_0001",
		"sender_domain==example.com",
		// Only authenticated submissions are counted: otherwise anyone could
		// spend the domain's quota by sending it mail.
		"sasl_username=~.+",
		// 500 messages per 3600 seconds, answered with a temporary failure.
		"action=rate(RL_0001/500/3600/450 4.7.1",
		// The last rule keeps everything else out of the policy.
		"id=DEFAULT; action=dunno",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("postfwd config is missing %q:\n%s", want, out)
		}
	}

	if strings.Contains(out, "shop.example") {
		t.Errorf("a domain with no limit was rendered:\n%s", out)
	}
	if strings.Contains(out, "_BURST") {
		t.Errorf("a burst rule was rendered for a domain with no burst allowance:\n%s", out)
	}
	if strings.Index(out, "id=DEFAULT") < strings.Index(out, "id=RL_0001") {
		t.Error("the DEFAULT rule is not last: postfwd stops at the first match, so everything would be accepted")
	}
}

// TestRenderPostfwdConfBurstAndReject covers the two other halves of the policy:
// a short-window allowance that has its own counter, and the permanent answer.
func TestRenderPostfwdConfBurstAndReject(t *testing.T) {
	out := string(RenderPostfwdConf([]models.Domain{{
		ID: 7, Name: "bulk.example", Active: true,
		OutboundRateLimit: 1000, OutboundRateBurst: 50,
		OutboundRateAction: models.RateActionReject,
	}}))

	// Separate counters: sharing one key would let the burst rule never fire
	// (the hourly bucket would always be the one that is hit first).
	hourKey := postfwdRateKey(out, "1000/3600")
	burstKey := postfwdRateKey(out, "50/60")
	if hourKey == "" || burstKey == "" {
		t.Fatalf("could not find both rate rules:\n%s", out)
	}
	if hourKey == burstKey {
		t.Fatalf("the hourly and burst rules share the counter key %q:\n%s", hourKey, out)
	}
	for _, want := range []string{
		"id=RL_0007",
		"id=RL_0007_BURST",
		"action=rate(RL_0007/1000/3600/554 5.7.1",
		"action=rate(RL_0007_BURST/50/60/554 5.7.1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("postfwd config is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "450 4.7.1") {
		t.Errorf("a rejecting domain still answers with a temporary failure:\n%s", out)
	}
}

// postfwdRateKey extracts the counter key of the rule whose count/window is
// countWindow, so a test can compare two keys without re-implementing the
// renderer.
func postfwdRateKey(conf, countWindow string) string {
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "action=rate(") {
			continue
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(line, "action=rate("), ")")
		// <key>/<count>/<window>/<reply...> — split off the trailing fields.
		parts := strings.SplitN(inner, "/", 4)
		if len(parts) < 4 {
			continue
		}
		if parts[1]+"/"+parts[2] == countWindow {
			return parts[0]
		}
	}
	return ""
}

// TestIsManagedPostfwdConfig decides whether the panel may touch /etc/postfwd.cf.
// Overwriting an operator's own postfwd rules on a host that never configured a
// limit here would be a data-loss bug, so the check is on the header the
// renderer writes, not on the file's existence.
func TestIsManagedPostfwdConfig(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "missing.cf")
	if !isManagedPostfwdConfig(missing) {
		t.Error("a missing file is not treated as a file the panel may create")
	}

	ours := filepath.Join(dir, "ours.cf")
	rendered := RenderPostfwdConf(nil)
	if err := os.WriteFile(ours, rendered, 0o644); err != nil {
		t.Fatal(err)
	}
	if !isManagedPostfwdConfig(ours) {
		t.Errorf("a file rendered by RenderPostfwdConf is not recognised as managed:\n%s", rendered)
	}

	theirs := filepath.Join(dir, "theirs.cf")
	if err := os.WriteFile(theirs, []byte("# my own rules\nid=RATE; sender=~.+; action=rate(own/10/60/450 4.7.1 no)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if isManagedPostfwdConfig(theirs) {
		t.Error("an operator's own postfwd.cf is mistaken for a managed file")
	}
}

// TestRenderPostfwdConfIsSorted keeps the file byte-identical across syncs, so
// an unchanged policy is not rewritten (and does not reload postfwd, which is
// what keeps the counters alive).
func TestRenderPostfwdConfIsSorted(t *testing.T) {
	domains := []models.Domain{
		{ID: 3, Name: "zeta.example", Active: true, OutboundRateLimit: 10},
		{ID: 1, Name: "alpha.example", Active: true, OutboundRateLimit: 20},
		{ID: 2, Name: "beta.example", Active: true, OutboundRateLimit: 30},
	}

	first := string(RenderPostfwdConf(domains))
	second := string(RenderPostfwdConf(domains))
	if first != second {
		t.Fatal("rendering the same domains twice produced different output")
	}

	alpha := strings.Index(first, "alpha.example")
	beta := strings.Index(first, "beta.example")
	zeta := strings.Index(first, "zeta.example")
	if alpha < 0 || beta < 0 || zeta < 0 || !(alpha < beta && beta < zeta) {
		t.Errorf("domains are not in name order:\n%s", first)
	}
}

// TestRenderPostfixMainCFAddsThePolicyHookOnlyWhenNeeded: an install that never
// set a limit must not gain a policy lookup per message, and one that did must
// get all three settings -- the default action is what keeps a stopped postfwd
// from becoming a mail outage.
func TestRenderPostfixMainCFAddsThePolicyHookOnlyWhenNeeded(t *testing.T) {
	noLimits := rateLimitSnapshot()
	noLimits.Domains[0].OutboundRateLimit = 0

	without := string(RenderPostfixMainCF(noLimits, "mail.example.com"))
	if strings.Contains(without, "check_policy_service") {
		t.Errorf("main.cf consults a policy server nobody configured:\n%s", without)
	}

	snap := rateLimitSnapshot()
	snap.Domains[1].OutboundRateLimit = 100
	with := string(RenderPostfixMainCF(snap, "mail.example.com"))
	for _, want := range []string{
		"smtpd_end_of_data_restrictions = check_policy_service inet:127.0.0.1:10040",
		"smtpd_policy_service_timeout = 10s",
		"smtpd_policy_service_default_action = DUNNO",
	} {
		if !strings.Contains(with, want) {
			t.Errorf("main.cf is missing %q:\n%s", want, with)
		}
	}
}

// TestHasRateLimitsIgnoresInactiveDomains: a disabled domain's limit is not a
// reason to run a policy daemon or to add a hook to main.cf.
func TestHasRateLimitsIgnoresInactiveDomains(t *testing.T) {
	snap := &models.Snapshot{Domains: []models.Domain{
		{ID: 1, Name: "off.example", Active: false, OutboundRateLimit: 10},
	}}
	if hasRateLimits(snap) {
		t.Error("an inactive domain counted as having a rate limit")
	}

	snap.Domains[0].Active = true
	if !hasRateLimits(snap) {
		t.Error("an active domain with a limit was not counted")
	}
}
