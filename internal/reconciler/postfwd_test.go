package reconciler

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/postfwd"
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

// postfwdRuleBlock returns the text of the rule with this id: from its id line
// up to the next rule. Empty when there is no such rule.
func postfwdRuleBlock(out, id string) string {
	start := strings.Index(out, "id="+id+"\n")
	if start < 0 {
		return ""
	}
	rest := out[start:]
	if next := strings.Index(rest[1:], "\nid="); next >= 0 {
		return rest[:next+1]
	}
	return rest
}

// postfwdRateKey returns the counter key of the rate rule whose count and window
// are "500/3600": the first argument of rate().
func postfwdRateKey(out, countAndWindow string) string {
	i := strings.Index(out, "/"+countAndWindow+"/")
	if i < 0 {
		return ""
	}
	head := out[:i]
	j := strings.LastIndex(head, "rate(")
	if j < 0 {
		return ""
	}
	return head[j+len("rate("):]
}

// TestRenderPostfwdConfCoversBothSubmissionPaths is the regression test for the
// bug that made a configured cap enforce nothing.
//
// Webmail submits to 127.0.0.1:25 without authenticating, so a rule that required
// `sasl_username` never matched it and postfwd answered DUNNO to exactly the mail
// the limit existed for. Each window is now two rules: one for submissions from
// this host, one for authenticated clients, sharing one counter.
func TestRenderPostfwdConfCoversBothSubmissionPaths(t *testing.T) {
	out := string(RenderPostfwdConf(rateLimitSnapshot().Domains))

	local := postfwdRuleBlock(out, "RL_0001_H_LOCAL")
	if local == "" {
		t.Fatalf("no rule for a submission from this host:\n%s", out)
	}
	if !strings.Contains(local, "sender_domain==example.com") {
		t.Errorf("the local rule does not scope itself to the domain:\n%s", local)
	}
	if !strings.Contains(local, "client_address==127.0.0.1") {
		t.Errorf("the local rule does not match submissions from this host:\n%s", local)
	}
	if strings.Contains(local, "sasl_username") {
		t.Errorf("the local rule requires SASL, so webmail can never match it:\n%s", local)
	}
	if !strings.Contains(local, "action=rate(RL_0001_H/500/3600/450 4.7.1") {
		t.Errorf("the local rule is not a 500/hour deferring rate limit:\n%s", local)
	}

	auth := postfwdRuleBlock(out, "RL_0001_H_AUTH")
	if auth == "" {
		t.Fatalf("no rule for an authenticated client:\n%s", out)
	}
	if !strings.Contains(auth, "sasl_username=~.+") {
		t.Errorf("the authenticated rule does not require SASL:\n%s", auth)
	}
	if !strings.Contains(auth, "client_address=~"+postfwd.RemoteClientPattern) {
		t.Errorf("the authenticated rule does not exclude this host, so a local message would be counted twice:\n%s", auth)
	}
	if !strings.Contains(auth, "action=rate(RL_0001_H/500/3600/450 4.7.1") {
		t.Errorf("the authenticated rule is not a 500/hour deferring rate limit:\n%s", auth)
	}

	// One message must cost one unit: both rules have to spend the same bucket.
	if n := strings.Count(out, "action=rate(RL_0001_H/"); n != 2 {
		t.Errorf("the hourly window has %d rules, want 2 (local and authenticated):\n%s", n, out)
	}
	if strings.Contains(out, "rate(RL_0001_H_LOCAL/") || strings.Contains(out, "rate(RL_0001_H_AUTH/") {
		t.Errorf("the two rules count into different buckets, so each would allow the full quota:\n%s", out)
	}
}

// TestRenderPostfwdConfMarksEveryWindowForTheDoctor: the canary and the per-domain
// probes are what `mailx-admin doctor` asks, so they must exist, answer a fixed
// reply, and sit ahead of the rate rules (a domain that is already over its cap
// still has to answer its probe).
func TestRenderPostfwdConfMarksEveryWindowForTheDoctor(t *testing.T) {
	out := string(RenderPostfwdConf(rateLimitSnapshot().Domains))

	if !strings.Contains(out, postfwd.CanarySender) || !strings.Contains(out, postfwd.CanaryReply) {
		t.Errorf("the canary rule is missing:\n%s", out)
	}
	if strings.Index(out, postfwd.CanarySender) > strings.Index(out, "id=RL_0001") {
		t.Errorf("the canary rule is not ahead of the rate rules:\n%s", out)
	}

	for _, id := range []string{"PROBE_0001_LOCAL", "PROBE_0001_AUTH"} {
		block := postfwdRuleBlock(out, id)
		if block == "" {
			t.Fatalf("the doctor has no probe rule %s:\n%s", id, out)
		}
		if !strings.Contains(block, "sender=="+postfwd.ProbeSender("example.com")) {
			t.Errorf("%s does not match the probe sender:\n%s", id, block)
		}
		if !strings.Contains(block, "action="+postfwd.ProbeReply) {
			t.Errorf("%s does not answer the probe reply:\n%s", id, block)
		}
		// A probe must never reach a rate rule: the reply has to be the probe's
		// own, and the rule has to come first.
		if strings.Contains(block, "rate(") {
			t.Errorf("%s counts against a rate, so checking a limit would spend it:\n%s", id, block)
		}
		if strings.Index(out, "id="+id) > strings.Index(out, "id=RL_0001_H_LOCAL") {
			t.Errorf("%s is behind the rate rules, so an over-quota domain would fail its own probe:\n%s", id, out)
		}
	}

	// A domain without a limit has nothing to probe and nothing to enforce.
	if strings.Contains(out, postfwd.ProbeSender("shop.example")) || strings.Contains(out, "shop.example") {
		t.Errorf("a domain with no limit was rendered:\n%s", out)
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
		"id=RL_0007_H_LOCAL",
		"id=RL_0007_H_AUTH",
		"id=RL_0007_BURST_LOCAL",
		"id=RL_0007_BURST_AUTH",
		"action=rate(RL_0007_H/1000/3600/554 5.7.1",
		"action=rate(RL_0007_BURST/50/60/554 5.7.1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("postfwd config is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "450 4.7.1 Rate limit exceeded") {
		t.Errorf("a rejecting domain still answers with a temporary failure:\n%s", out)
	}
}

// TestRenderPostfwdConfRendersEveryWindow pins the day and month caps: one
// counter per window, each with its own interval and its own pair of rules.
//
// The key part is not cosmetic. postfwd keys a rate counter by the first argument
// of rate(), so two windows sharing a key would share one bucket and whichever
// limit came first would consume the other's allowance.
func TestRenderPostfwdConfRendersEveryWindow(t *testing.T) {
	out := string(RenderPostfwdConf([]models.Domain{{
		ID: 12, Name: "news.example", Active: true,
		OutboundRateLimit: 500, OutboundRateDaily: 4000, OutboundRateMonthly: 60000,
		OutboundRateBurst: 50, OutboundRateAction: models.RateActionDefer,
	}}))

	windows := []struct {
		id    string
		count int
		span  int
	}{
		{"RL_0012_H", 500, postfwdRateWindow},
		{"RL_0012_D", 4000, postfwdDailyWindow},
		{"RL_0012_M", 60000, postfwdMonthlyWindow},
		{"RL_0012_BURST", 50, postfwdBurstWindow},
	}
	seen := map[string]bool{}
	for _, w := range windows {
		want := "action=rate(" + w.id + "/" + strconv.Itoa(w.count) + "/" + strconv.Itoa(w.span) + "/"
		if !strings.Contains(out, want) {
			t.Errorf("the %s window is missing (%q):\n%s", w.id, want, out)
		}
		for _, suffix := range []string{"_LOCAL", "_AUTH"} {
			if !strings.Contains(out, "id="+w.id+suffix+"\n") {
				t.Errorf("the %s window has no %s rule, so one submission path is unlimited:\n%s", w.id, suffix, out)
			}
		}
		if seen[w.id] {
			t.Errorf("the counter key %q is used by two windows:\n%s", w.id, out)
		}
		seen[w.id] = true
	}
}

// TestRenderPostfwdConfDailyOnly: a domain whose only cap is a daily one still
// gets enforced rules -- "no hourly limit" must not mean "no limit".
func TestRenderPostfwdConfDailyOnly(t *testing.T) {
	out := string(RenderPostfwdConf([]models.Domain{
		{ID: 4, Name: "daily.example", Active: true, OutboundRateDaily: 200},
	}))
	if !strings.Contains(out, "action=rate(RL_0004_D/200/86400/") {
		t.Errorf("a domain with only a daily cap has no daily rule:\n%s", out)
	}
	if strings.Contains(out, "rate(RL_0004_H") {
		t.Errorf("a domain with no hourly cap has an hourly rule:\n%s", out)
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

// TestIsManagedPostfwdConfig: the panel may create the file, and may replace one
// it wrote, but must not silently take over an operator's own rules.
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
		"smtpd_end_of_data_restrictions = check_policy_service inet:" + postfwd.PolicyAddr,
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
