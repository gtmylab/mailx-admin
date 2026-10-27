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

	// postfwdCanaryID names the unconditional rule at the top of the file. Its
	// only job is to be recognisable: the doctor sends it a message and expects
	// its answer. Anything else -- DUNNO, a different reply, no answer at all --
	// means the running daemon is not enforcing the file the panel wrote.
	postfwdCanaryID   = "MAILX_CANARY"
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
// probes with, one rate rule pair per cap and domain, and a final DUNNO so
// everything else is untouched.
//
// The syntax is postfwd's, not Postfix's:
//
//	id=RL_0001_H_LOCAL
//	  sender_domain==example.com
//	  client_address==127.0.0.1
//	  action=rate(RL_0001_H/500/3600/450 4.7.1 ...)
//
// `rate(<key>/<count>/<seconds>/<reply>)` counts messages per key and answers
// <reply> once <count> messages arrived within <seconds>; below <count> the
// action is DUNNO, so the next rule still runs. That is what makes several
// windows for one domain possible: the message has to pass the hourly, daily and
// monthly rule in turn, and any one of them can stop it.
//
// # Why a window is two rules
//
// A message reaches Postfix through one of two paths, and only one of them is
// authenticated:
//
//   - Webmail on this host (Roundcube, the panel's own test-send, anything that
//     submits to 127.0.0.1:25) arrives from the loopback address and carries no
//     SASL username at all.
//   - A mail client arrives over 587/465 and carries the mailbox it logged in as.
//
// A single rule that required `sasl_username` therefore never matched webmail,
// and postfwd answered DUNNO to every message the panel was supposed to stop:
// the cap was configured, written, loaded, and enforced on nothing. Each window
// is now two rules that cover both paths and share one counter:
//
//	RL_0001_H         the counter key (one window = one bucket)
//	RL_0001_H_LOCAL:   sender_domain==<domain> + client_address==<loopback>
//	RL_0001_H_AUTH:    sender_domain==<domain> + sasl_username=~.+ + remote client
//
// The two condition sets are disjoint -- the authenticated rule excludes the
// loopback addresses with postfwd.RemoteClientPattern -- which is what makes
// sharing the key safe: exactly one of them matches a given message, so a
// message costs one unit and not two.
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
// the canary at the top answer a fixed 554 for a sender nothing else can use
// (postfwd.ProbeSender, postfwd.CanarySender). They sit ahead of the rate rules,
// so asking them costs no allowance -- checking a limit must not spend it. The
// doctor sends exactly those messages and reads the answers, which turns "the
// rule never matches" from a silent failure into a warning that names the path
// that is broken.
//
// Domains are sorted by name so the file is stable: postfwd's counters survive a
// reload (--keep_rates), and an unstable file would make every sync look like a
// change.
func RenderPostfwdConf(domains []models.Domain) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin -- DO NOT EDIT\n")
	b.WriteString("# Outgoing rate limits per sender domain, asked by Postfix through\n")
	b.WriteString("# smtpd_end_of_data_restrictions (see main.cf).\n")
	b.WriteString("# Windows are rolling (3600/86400/2592000s); the key is the rule id and\n")
	b.WriteString("# --keep_rates keeps counters across reloads.\n")
	b.WriteString("# Each window is two rules (local submission / authenticated submission)\n")
	b.WriteString("# sharing one counter; the probe and canary rules are what `mailx-admin\n")
	b.WriteString("# doctor` asks to prove the limits are really enforced.\n\n")

	// The canary comes first and is unconditional: it is the answer to "is the
	// daemon enforcing this file at all".
	fmt.Fprintf(&b, "id=%s; sender==%s; action=%s\n\n",
		postfwdCanaryID, postfwd.CanarySender, postfwd.CanaryReply)

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
			writePostfwdRateRules(&b, base+"_H", d, d.OutboundRateLimit, postfwdRateWindow, "hour")
		}
		if d.OutboundRateDaily > 0 {
			writePostfwdRateRules(&b, base+"_D", d, d.OutboundRateDaily, postfwdDailyWindow, "day")
		}
		if d.OutboundRateMonthly > 0 {
			writePostfwdRateRules(&b, base+"_M", d, d.OutboundRateMonthly, postfwdMonthlyWindow, "month")
		}
		if d.OutboundRateBurst > 0 {
			writePostfwdRateRules(&b, base+"_BURST", d, d.OutboundRateBurst, postfwdBurstWindow, "minute")
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

// writePostfwdRateRules emits the two rules that make up one window of one
// domain: the counter key is base, shared by both, and each rule carries the
// counter with the same count, interval and reply.
func writePostfwdRateRules(b *bytes.Buffer, base string, d models.Domain, count, window int, unit string) {
	reply := fmt.Sprintf("450 4.7.1 Rate limit exceeded for %s: %d messages per %s. Try again later.",
		d.Name, count, unit)
	if d.RateAction() == models.RateActionReject {
		reply = fmt.Sprintf("554 5.7.1 Rate limit exceeded for %s: %d messages per %s.",
			d.Name, count, unit)
	}

	// Submitted from this host (webmail, the panel's own mail, cron jobs that go
	// through an smtpd). No sasl condition: this traffic has no SASL at all.
	fmt.Fprintf(b, "id=%s_LOCAL\n", base)
	fmt.Fprintf(b, "  sender_domain==%s\n", d.Name)
	for _, addr := range postfwd.LoopbackClients {
		fmt.Fprintf(b, "  client_address==%s\n", addr)
	}
	fmt.Fprintf(b, "  action=rate(%s/%d/%d/%s)\n\n", base, count, window, reply)

	// Submitted by an authenticated client from anywhere else. The client
	// condition is what keeps the message from also matching the local rule and
	// being counted twice against the same key.
	fmt.Fprintf(b, "id=%s_AUTH\n", base)
	fmt.Fprintf(b, "  sender_domain==%s\n", d.Name)
	b.WriteString("  sasl_username=~.+\n")
	fmt.Fprintf(b, "  client_address=~%s\n", postfwd.RemoteClientPattern)
	fmt.Fprintf(b, "  action=rate(%s/%d/%d/%s)\n\n", base, count, window, reply)
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
