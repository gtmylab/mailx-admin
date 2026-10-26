package reconciler

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/gtmylab/mailx-admin/internal/models"
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

// RenderPostfwdConf produces /etc/postfwd.cf: one rate rule per cap and domain,
// and a final DUNNO so everything else is untouched.
//
// The syntax is postfwd's, not Postfix's, and it is the documented four-argument
// form (postfwd.org/example-cfg.txt):
//
//	id=RL_0001_H
//	  sender_domain==example.com
//	  sasl_username=~.+
//	  action=rate(RL_0001_H/500/3600/450 4.7.1 ...)
//
// `rate(<key>/<count>/<seconds>/<reply>)` counts messages per key and answers
// <reply> once <count> messages arrived within <seconds>; below <count> the
// action is DUNNO, so the next rule still runs. That is what makes several
// windows for one domain possible: the message has to pass the hourly, daily and
// monthly rule in turn, and any one of them can stop it.
//
// The key is the rule's own id. It has to be one token (no `/`, because `/`
// separates the rate arguments) and unique per rule: sharing a key between two
// windows would put the hourly and the daily count in one bucket, and whichever
// limit came first would consume the other's allowance.
//
// `sasl_username=~.+` restricts the rule to authenticated submissions. Without
// it the limit would also count *inbound* mail whose envelope sender happens to
// claim our domain -- anyone could spend a customer's quota by sending them
// mail. It also means the limit only sees port 587/465 traffic: locally
// generated bounces and cron mail never pass an smtpd, so they are not counted
// (they are also not what these limits exist for).
//
// The daily and monthly numbers are the panel's, not postfwd's: a marketing
// domain needs a cap that a single bad afternoon cannot exhaust.
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
	b.WriteString("# --keep_rates keeps counters across reloads.\n\n")

	limited := make([]models.Domain, 0, len(domains))
	for _, d := range domains {
		if d.Active && d.RateLimited() {
			limited = append(limited, d)
		}
	}
	sortDomainsByName(limited)

	for _, d := range limited {
		id := postfwdRuleID("RL", d.ID)
		// Each window gets its own id and its own counter. Shortest first, so
		// the cheapest rejection (the hourly cap) is asked before the day and
		// month counters are touched.
		if d.OutboundRateLimit > 0 {
			writePostfwdRule(&b, id+"_H", d, d.OutboundRateLimit, postfwdRateWindow, "hour")
		}
		if d.OutboundRateDaily > 0 {
			writePostfwdRule(&b, id+"_D", d, d.OutboundRateDaily, postfwdDailyWindow, "day")
		}
		if d.OutboundRateMonthly > 0 {
			writePostfwdRule(&b, id+"_M", d, d.OutboundRateMonthly, postfwdMonthlyWindow, "month")
		}
		if d.OutboundRateBurst > 0 {
			writePostfwdRule(&b, id+"_BURST", d, d.OutboundRateBurst, postfwdBurstWindow, "minute")
		}
	}

	// Anything not matched above is accepted. Without this last rule postfwd
	// would apply its own default (DUNNO in v1, but a config file is easier to
	// reason about when it says what it means).
	b.WriteString("# Everything else: no policy from postfwd.\n")
	b.WriteString("id=DEFAULT; action=dunno\n")
	return b.Bytes()
}

func writePostfwdRule(b *bytes.Buffer, id string, d models.Domain, count, window int, unit string) {
	reply := fmt.Sprintf("450 4.7.1 Rate limit exceeded for %s: %d messages per %s. Try again later.",
		d.Name, count, unit)
	if d.RateAction() == models.RateActionReject {
		reply = fmt.Sprintf("554 5.7.1 Rate limit exceeded for %s: %d messages per %s.",
			d.Name, count, unit)
	}

	fmt.Fprintf(b, "id=%s\n", id)
	fmt.Fprintf(b, "  sender_domain==%s\n", d.Name)
	b.WriteString("  sasl_username=~.+\n")
	// The key is the id: one token, unique per rule, so the hourly and the
	// burst counters never collide.
	fmt.Fprintf(b, "  action=rate(%s/%d/%d/%s)\n\n", id, count, window, reply)
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
