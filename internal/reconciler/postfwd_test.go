package reconciler

import (
	"os"
	"path/filepath"
	"regexp"
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
//
// The marker rules put everything on the id line (`id=X; sender==...;
// action=...`), so the id is followed by either a newline or a semicolon.
func postfwdRuleBlock(out, id string) string {
	start := strings.Index(out, "id="+id+"\n")
	if start < 0 {
		start = strings.Index(out, "id="+id+";")
	}
	if start < 0 {
		return ""
	}
	rest := out[start:]
	if next := strings.Index(rest[1:], "\nid="); next >= 0 {
		return rest[:next+1]
	}
	return rest
}

// postfwdRateArgs returns the arguments of every rate() action in the rendered
// file, in order, as "<item>/<count>/<seconds>/<reply>".
func postfwdRateArgs(out string) []string {
	var args []string
	for _, m := range regexp.MustCompile(`action=rate\(([^)]*)\)`).FindAllStringSubmatch(out, -1) {
		args = append(args, m[1])
	}
	return args
}

// TestRenderPostfwdConfCoversBothSubmissionPaths is the regression test for the
// bug that made a configured cap ignore webmail.
//
// Webmail submits to 127.0.0.1:25 without authenticating, so a rule that required
// `sasl_username` never matched it and postfwd answered DUNNO to exactly the mail
// the limit existed for. The rule now matches on `sender_domain` alone -- a
// property of the message, not of the path it took -- so the webmail path, a
// client on 587/465 and an IPv6 submission all reach the same rule.
func TestRenderPostfwdConfCoversBothSubmissionPaths(t *testing.T) {
	out := string(RenderPostfwdConf(rateLimitSnapshot().Domains))

	rule := postfwdRuleBlock(out, "RL_0001_H")
	if rule == "" {
		t.Fatalf("no rule for the hourly cap:\n%s", out)
	}
	if !strings.Contains(rule, "sender_domain==example.com") {
		t.Errorf("the rule does not scope itself to the domain:\n%s", rule)
	}
	if strings.Contains(rule, "sasl_username") {
		t.Errorf("the rule requires SASL, so webmail can never match it:\n%s", rule)
	}
	if strings.Contains(rule, "client_address") {
		t.Errorf("the rule restricts the client address, so one of the submission paths falls through:\n%s", rule)
	}
	if !strings.Contains(rule, "action=rate(sender_domain/500/3600/450 4.7.1") {
		t.Errorf("the rule is not a 500/hour deferring rate limit on the sender domain:\n%s", rule)
	}

	// One message costs one unit: a second rule for the same window would count
	// the same message twice, or hand the whole quota out twice.
	if n := strings.Count(out, "rate(sender_domain/500/3600/"); n != 1 {
		t.Errorf("the hourly window is counted by %d rules, want 1:\n%s", n, out)
	}
}

// TestRenderPostfwdConfKeysRateOnARealItem is the regression test for v1.6.38.
//
// That release rendered `action=rate(RL_0001_H/500/3600/...)`, treating the rule
// id as the counter's name. postfwd does the opposite: it reads the first
// argument as the name of a request item and wraps its entire counting block --
// bucket creation, increment, comparison -- in `if (defined $request->{$item})`.
// A rule id is never a request item, so nothing was counted and no cap could
// ever fire, while every probe in `doctor` still passed because the probe rules
// are plain rejects that never reach rate().
func TestRenderPostfwdConfKeysRateOnARealItem(t *testing.T) {
	// The items the renderer may count on: `sender_domain` for the per-domain
	// caps, `sender` for the rate canary's own bucket.
	allowed := map[string]bool{"sender_domain": true, "sender": true}

	args := postfwdRateArgs(string(RenderPostfwdConf(rateLimitSnapshot().Domains)))
	if len(args) == 0 {
		t.Fatal("the rendered file has no rate() rule at all")
	}
	for _, a := range args {
		key := strings.SplitN(a, "/", 2)[0]
		if !allowed[key] {
			t.Errorf("rate() is keyed on %q, which is not a postfwd request item: nothing would be counted and the cap would never fire (action=rate(%s))", key, a)
		}
	}
}

// TestRenderPostfwdConfMarksEveryWindowForTheDoctor: the canaries and the
// per-domain probes are what `mailx-admin doctor` asks, so they must exist,
// answer a fixed reply, and sit ahead of the rate rules (a domain that is already
// over its cap still has to answer its probe).
func TestRenderPostfwdConfMarksEveryWindowForTheDoctor(t *testing.T) {
	out := string(RenderPostfwdConf(rateLimitSnapshot().Domains))

	if !strings.Contains(out, postfwd.CanarySender) || !strings.Contains(out, postfwd.CanaryReply) {
		t.Errorf("the canary rule is missing:\n%s", out)
	}

	rateCanary := postfwdRuleBlock(out, postfwdRateCanaryID)
	if rateCanary == "" {
		t.Fatalf("the doctor has no rate() canary rule:\n%s", out)
	}
	if !strings.Contains(rateCanary, "sender=="+postfwd.RateCanarySender) {
		t.Errorf("%s does not match the rate canary sender:\n%s", postfwdRateCanaryID, rateCanary)
	}
	// It has to be a rate() rule. A plain reject answers correctly even when no
	// counter is kept, which is the failure this rule exists to expose.
	if !strings.Contains(rateCanary, "action=rate(sender/1/") {
		t.Errorf("%s is not a rate() rule, so it cannot prove that counting works:\n%s", postfwdRateCanaryID, rateCanary)
	}
	if !strings.Contains(rateCanary, postfwd.RateCanaryReply) {
		t.Errorf("%s does not answer the rate canary reply:\n%s", postfwdRateCanaryID, rateCanary)
	}

	for _, marker := range []string{postfwd.CanarySender, postfwd.RateCanarySender} {
		if strings.Index(out, marker) > strings.Index(out, "id=RL_0001") {
			t.Errorf("the marker %q is not ahead of the rate rules:\n%s", marker, out)
		}
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
		if strings.Index(out, "id="+id) > strings.Index(out, "id=RL_0001_H") {
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
// a short-window allowance with its own bucket, and the permanent answer.
func TestRenderPostfwdConfBurstAndReject(t *testing.T) {
	out := string(RenderPostfwdConf([]models.Domain{{
		ID: 7, Name: "bulk.example", Active: true,
		OutboundRateLimit: 1000, OutboundRateBurst: 50,
		OutboundRateAction: models.RateActionReject,
	}}))

	// Both windows count the same item, so the only thing that keeps their
	// buckets apart is the rule id postfwd folds into the counter key. Sharing
	// one bucket would make the burst allowance invisible: the hourly bucket is
	// the one that would be hit first.
	for _, want := range []string{
		"id=RL_0007_H\n",
		"id=RL_0007_BURST\n",
		"action=rate(sender_domain/1000/3600/554 5.7.1",
		"action=rate(sender_domain/50/60/554 5.7.1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("postfwd config is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "450 4.7.1 Rate limit exceeded") {
		t.Errorf("a rejecting domain still answers with a temporary failure:\n%s", out)
	}
}

// TestRenderPostfwdConfRendersEveryWindow pins the day and month caps: one rule
// per window, each with its own interval and its own bucket.
//
// The bucket part is not cosmetic. Every window counts the same item
// (`sender_domain`), so what separates two windows is the rule id postfwd folds
// into the counter key; sharing a key would make whichever limit came first
// consume the other's allowance.
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
	for _, w := range windows {
		block := postfwdRuleBlock(out, w.id)
		if block == "" {
			t.Fatalf("the %s window is missing:\n%s", w.id, out)
		}
		want := "action=rate(sender_domain/" + strconv.Itoa(w.count) + "/" + strconv.Itoa(w.span) + "/"
		if !strings.Contains(block, want) {
			t.Errorf("the %s window is not %d messages per %ds (%q):\n%s", w.id, w.count, w.span, want, block)
		}
		// One rule per window: a second one would cost a message two units.
		if n := strings.Count(out, want); n != 1 {
			t.Errorf("the %s window is counted by %d rules, want 1:\n%s", w.id, n, out)
		}
	}
}

// TestRenderPostfwdConfDailyOnly: a domain whose only cap is a daily one still
// gets enforced rules -- "no hourly limit" must not mean "no limit".
func TestRenderPostfwdConfDailyOnly(t *testing.T) {
	out := string(RenderPostfwdConf([]models.Domain{
		{ID: 4, Name: "daily.example", Active: true, OutboundRateDaily: 200},
	}))
	if !strings.Contains(out, "action=rate(sender_domain/200/86400/") {
		t.Errorf("a domain with only a daily cap has no daily rule:\n%s", out)
	}
	if strings.Contains(out, "id=RL_0004_H\n") {
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
