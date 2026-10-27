package reconciler

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/postfwd"
)

// postfwdRateWindow is the window the hourly cap is counted over,
// postfwdDailyWindow and postfwdMonthlyWindow the day and month ones, and
// postfwdBurstWindow the window a burst allowance is counted over.
//
// The day and month windows are 86400 and 2592000 seconds, not calendar
// periods: postfwd counts a sliding interval and has no way to reset a counter
// at midnight. The panel says "rolling" wherever the difference is visible.
const (
	postfwdRateWindow    = 3600
	postfwdDailyWindow   = 86400
	postfwdMonthlyWindow = 2592000 // 30 days
	postfwdBurstWindow   = 60

	// postfwdRateItem is the postfwd request item a cap is counted on: the
	// domain part of the envelope sender.
	//
	// It is not a label of our choosing. postfwd reads the first argument of
	// rate() as the name of a request item, looks it up in the request, and skips
	// the counting block when the lookup fails -- see RenderPostfwdConf.
	postfwdRateItem = "sender_domain"

	// postfwdCanaryID names the unconditional rule at the top of the file. Its
	// only job is to be recognisable: the doctor sends it a message and expects
	// its answer. Anything else -- DUNNO, a different reply, no answer at all --
	// means the running daemon is not enforcing the file the panel wrote.
	postfwdCanaryID = "MAILX_CANARY"

	// postfwdRateCanaryID names the rule that proves rate() itself counts, over
	// postfwdRateCanaryWindow seconds. It answers a different question from the
	// canary above: a plain reject rule never reaches a rate() action, so it
	// still answers correctly in a file whose rate() rules count nothing.
	postfwdRateCanaryID     = "MAILX_RATE_CANARY"
	postfwdRateCanaryWindow = 60

	postfwdProbeIDFmt = "PROBE_%04d"
)

// isManagedPostfwdConfig reports whether path does not exist yet (so the panel
// may create it) or already carries the header RenderPostfwdConf writes.
//
// The distinction matters for an operator who runs postfwd for their own rules:
// the panel must not overwrite /etc/postfwd.cf just because it happens to exist.
// Once a limit is configured in the panel, the file is the panel's -- with a
// backup kept by the reconciler, like every other managed file.
func isManagedPostfwdConfig(path string) bool {
	src, err := os.ReadFile(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	return bytes.HasPrefix(src, []byte("# Managed by mailx-admin"))
}

// serviceUnitExists reports whether systemd knows a unit by this name.
//
// It is what keeps the postfwd reload from failing the whole sync on an install
// that does not have postfwd: `systemctl reload-or-restart` on a unit that does
// not exist exits non-zero, and the reconciler treats that as an error.
func serviceUnitExists(ctx context.Context, name string) bool {
	return runCmd(ctx, commandTimeout, "systemctl", "cat", name) == nil
}

// hasRateLimits reports whether any active domain has an outgoing limit, in
// which case the postfwd config and the Postfix policy hook are both emitted.
func hasRateLimits(snap *models.Snapshot) bool {
	for _, d := range snap.Domains {
		if d.Active && d.RateLimited() {
			return true
		}
	}
	return false
}

// RenderPostfwdConf produces /etc/postfwd.cf: the marker rules the doctor
// probes with, one rate rule per cap and domain, and a final DUNNO so
// everything else is untouched.
//
// The syntax is postfwd's, not Postfix's:
//
//	id=RL_0001_H
//	  sender_domain==example.com
//	  action=rate(sender_domain/500/3600/450 4.7.1 ...)
//
// `rate(<item>/<count>/<seconds>/<reply>)` counts messages per value of <item>
// and answers <reply> once <count> messages arrived within <seconds>; below
// <count> the action is DUNNO, so the next rule still runs. That is what makes
// several windows for one domain possible: the message has to pass the hourly,
// daily and monthly rule in turn, and any one of them can stop it.
//
// # Why the first argument of rate() is an item, not a name we choose
//
// postfwd does not count before it knows *what* to count: rate() reads its first
// argument as the name of a request item, looks that name up in the request, and
// wraps the whole counting block -- bucket creation, increment, comparison,
// reply -- in `if (defined $request->{$item})`. A first argument it cannot find
// there is not a harmless label: nothing is counted, no bucket is ever created,
// and the rule answers DUNNO for every message, for ever. Both the Debian
// package (postfwd 1.35) and upstream postfwd3 behave this way.
//
// v1.6.38 passed the rule id instead -- `action=rate(RL_0001_H/500/3600/...)` --
// believing it merely named the bucket. Nothing counted, so nothing capped: a
// domain limited to 2/day sent six messages and postfwd answered DUNNO to all
// six, while the doctor reported the limits enforced, because its probes are
// plain rejects that never reach a rate() rule.
//
// The key is `sender_domain`, a request item postfwd derives from the envelope
// sender, and the same thing the rule matches on -- so one rule counts one
// domain across every submission path. The bucket a rule counts into is the rule
// id plus its limit (`<id>+<count>_<seconds>`), so one rule per window keeps the
// windows independent and a message costs exactly one unit. Nothing is split by
// client address or SASL: `sender_domain` matches webmail, which submits from
// the loopback address without authenticating, and a mail client on 587/465
// alike.
//
// `sender_domain` is the envelope sender's domain: the cap covers what the
// domain sends, not what is sent to it, so inbound mail cannot spend a
// customer's quota. Mail injected with sendmail(1) or by a local agent (cron
// output, bounces, the panel's own notifications) never passes an smtpd, so
// Postfix never asks postfwd about it and it is not counted -- these caps exist
// for what users submit, not for what the server generates.
//
// # Why the marker rules
//
// The first two rules of each domain (`PROBE_0001_LOCAL`, `PROBE_0001_AUTH`) and
// the two canaries at the top answer a fixed 554 for senders nothing else can
// use (postfwd.ProbeSender, postfwd.CanarySender, postfwd.RateCanarySender).
// They sit ahead of the rate rules, so asking them costs no allowance --
// checking a limit must not spend it. The doctor sends exactly those messages
// and reads the answers, which turns two silent failures into warnings: "the
// rule never matches" (the probes) and "the rule never counts" (the rate canary,
// the only rule that reaches rate() with a key that belongs to nobody).
//
// Domains are sorted by name so the file is stable: postfwd's counters survive a
// reload (--keep_rates), and an unstable file would make every sync look like a
// change.
func RenderPostfwdConf(domains []models.Domain) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin -- DO NOT EDIT\n")
	b.WriteString("# Outgoing rate limits per sender domain, asked by Postfix through\n")
	b.WriteString("# smtpd_end_of_data_restrictions (see main.cf).\n")
	b.WriteString("# Windows are rolling (3600/86400/2592000s). rate() is keyed on the\n")
	b.WriteString("# sender domain -- postfwd counts nothing when its first argument is not\n")
	b.WriteString("# one of its request items -- and the bucket is the rule id, so one rule\n")
	b.WriteString("# per window is enough. --keep_rates keeps counters across reloads. The\n")
	b.WriteString("# probe and canary rules are what `mailx-admin doctor` asks to prove the\n")
	b.WriteString("# limits are really enforced.\n\n")

	// The canary comes first and is unconditional: it is the answer to "is the
	// daemon enforcing this file at all".
	fmt.Fprintf(&b, "id=%s; sender==%s; action=%s\n\n",
		postfwdCanaryID, postfwd.CanarySender, postfwd.CanaryReply)

	// The rate canary is the only rule that reaches rate() with a key belonging
	// to nobody, and therefore the only answer to "do the caps count?" -- the
	// plain rejects above answer even in a file whose rate() rules count nothing.
	// One message per minute is allowed and the next is refused, so the doctor
	// asks twice; the bucket is keyed on this sender and expires on its own, so
	// asking never spends a customer's allowance.
	fmt.Fprintf(&b, "id=%s; sender==%s; action=rate(sender/1/%d/%s)\n\n",
		postfwdRateCanaryID, postfwd.RateCanarySender, postfwdRateCanaryWindow, postfwd.RateCanaryReply)

	limited := make([]models.Domain, 0, len(domains))
	for _, d := range domains {
		if d.Active && d.RateLimited() {
			limited = append(limited, d)
		}
	}
	sortDomainsByName(limited)

	for _, d := range limited {
		base := postfwdRuleID("RL", d.ID)
		// The probes go before the rate rules: a domain that is already over its
		// cap must still answer the probe, or a working limit would read as a
		// broken one.
		writePostfwdProbes(&b, d)
		// Each window gets its own counter. Shortest first, so the cheapest
		// rejection (the hourly cap) is asked before the day and month counters
		// are touched.
		if d.OutboundRateLimit > 0 {
			writePostfwdRateRule(&b, base+"_H", d, d.OutboundRateLimit, postfwdRateWindow, "hour")
		}
		if d.OutboundRateDaily > 0 {
			writePostfwdRateRule(&b, base+"_D", d, d.OutboundRateDaily, postfwdDailyWindow, "day")
		}
		if d.OutboundRateMonthly > 0 {
			writePostfwdRateRule(&b, base+"_M", d, d.OutboundRateMonthly, postfwdMonthlyWindow, "month")
		}
		if d.OutboundRateBurst > 0 {
			writePostfwdRateRule(&b, base+"_BURST", d, d.OutboundRateBurst, postfwdBurstWindow, "minute")
		}
	}

	// Anything not matched above is accepted. Without this last rule postfwd
	// would apply its own default (DUNNO in v1, but a config file is easier to
	// reason about when it says what it means).
	b.WriteString("# Everything else: no policy from postfwd.\n")
	b.WriteString("id=DEFAULT; action=dunno\n")
	return b.Bytes()
}

// writePostfwdProbes emits the two marker rules the doctor uses to prove that
// this domain's rules are reachable, one per submission path.
//
// They are plain rejects, not rate() rules: the doctor may ask as often as it
// likes and must never move a counter, because a check that spends the quota it
// is checking is worse than no check.
func writePostfwdProbes(b *bytes.Buffer, d models.Domain) {
	id := fmt.Sprintf(postfwdProbeIDFmt, d.ID)
	sender := postfwd.ProbeSender(d.Name)

	// Local submission: the path webmail takes, unauthenticated, from this host.
	fmt.Fprintf(b, "id=%s_LOCAL\n", id)
	fmt.Fprintf(b, "  sender_domain==%s\n", d.Name)
	fmt.Fprintf(b, "  sender==%s\n", sender)
	for _, addr := range postfwd.LoopbackClients {
		fmt.Fprintf(b, "  client_address==%s\n", addr)
	}
	fmt.Fprintf(b, "  action=%s\n\n", postfwd.ProbeReply)

	// Authenticated submission from somewhere else.
	fmt.Fprintf(b, "id=%s_AUTH\n", id)
	fmt.Fprintf(b, "  sender_domain==%s\n", d.Name)
	fmt.Fprintf(b, "  sender==%s\n", sender)
	b.WriteString("  sasl_username=~.+\n")
	fmt.Fprintf(b, "  client_address=~%s\n", postfwd.RemoteClientPattern)
	fmt.Fprintf(b, "  action=%s\n\n", postfwd.ProbeReply)
}

// writePostfwdRateRule emits one window of one domain: the rule matches every
// message whose envelope sender is in the domain and counts it in a rate()
// bucket keyed on that domain.
//
// One rule, not one per submission path: `sender_domain` matches webmail
// (loopback, no SASL) and a mail client on 587/465 (SASL) alike, so a single
// rule covers both and a message can only be counted once -- which is also why
// there is no client-address condition to get wrong.
//
// The first argument of rate() has to be a request item: see
// RenderPostfwdConf for what postfwd does when it is not.
func writePostfwdRateRule(b *bytes.Buffer, id string, d models.Domain, count, window int, unit string) {
	reply := fmt.Sprintf("450 4.7.1 Rate limit exceeded for %s: %d messages per %s. Try again later.",
		d.Name, count, unit)
	if d.RateAction() == models.RateActionReject {
		reply = fmt.Sprintf("554 5.7.1 Rate limit exceeded for %s: %d messages per %s.",
			d.Name, count, unit)
	}

	fmt.Fprintf(b, "id=%s\n", id)
	fmt.Fprintf(b, "  sender_domain==%s\n", d.Name)
	fmt.Fprintf(b, "  action=rate(%s/%d/%d/%s)\n\n", postfwdRateItem, count, window, reply)
}

// postfwdCanaryWait bounds how long a sync waits for the reloaded daemon to
// answer, and postfwdCanaryRetry how often it asks.
//
// A reload is asynchronous: `systemctl reload` returns once the signal has been
// delivered, and postfwd re-reads the file a moment later.
const (
	postfwdCanaryWait  = 5 * time.Second
	postfwdCanaryRetry = 500 * time.Millisecond
)

// verifyPostfwdCanary asks the running postfwd the one question the rendered
// config answers unconditionally: does a message from postfwd.CanarySender get
// postfwd.CanaryReply?
//
// The reload exiting 0 proves nothing about enforcement -- it proves systemd
// accepted a signal. This is the check that turns "written, loaded, enforced on
// nothing" into a warning in the sync result instead of a limit nobody notices
// is missing.
func verifyPostfwdCanary(ctx context.Context) error {
	req := postfwd.Request{
		Sender:        postfwd.CanarySender,
		Recipient:     "postmaster@example.invalid",
		ClientAddress: "127.0.0.1",
		QueueID:       "MAILXSYNC",
	}

	deadline := time.Now().Add(postfwdCanaryWait)
	var lastErr error
	for {
		resp, err := postfwd.Ask(ctx, postfwd.PolicyAddr, req)
		if err == nil {
			if resp.Action == postfwd.CanaryReply {
				return nil
			}
			lastErr = fmt.Errorf("it answered %q to the canary sender instead of %q",
				resp.Action, postfwd.CanaryReply)
		} else {
			lastErr = err
		}

		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(postfwdCanaryRetry):
		}
	}
}

// postfwdRuleID builds an id postfwd accepts: letters, digits and underscore
// only. The numeric domain id is added so the id is unique even if two domains
// share a sanitized name.
func postfwdRuleID(prefix string, domainID int64) string {
	return fmt.Sprintf("%s_%04d", prefix, domainID)
}

// sortDomainsByName keeps the rendered file deterministic.
func sortDomainsByName(domains []models.Domain) {
	for i := 1; i < len(domains); i++ {
		for j := i; j > 0 && domains[j].Name < domains[j-1].Name; j-- {
			domains[j], domains[j-1] = domains[j-1], domains[j]
		}
	}
}
