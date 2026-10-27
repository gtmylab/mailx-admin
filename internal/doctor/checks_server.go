package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/execx"
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/postfwd"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
	"github.com/gtmylab/mailx-admin/internal/seed"
)

// serverStateCheck compares the mailboxes and domains in the server's own
// configuration with the panel's. This is the "I created a user with useradd and
// the panel does not show it" answer: the panel lists what is in its database,
// and everything else has to be imported.
func serverStateCheck(ctx context.Context, opts Options) Check {
	if opts.Config == nil || opts.Store == nil {
		return Check{}
	}

	found, err := seed.Scan(seed.Options{
		PostfixConfDir:    opts.Config.Mail.PostfixConfDir,
		DovecotConfDir:    opts.Config.Mail.DovecotConfDir,
		OpenDKIMDir:       opts.Config.Mail.OpenDKIMDir,
		PrimaryDomainFile: opts.Config.Mail.PrimaryDomainFile,
	})
	if err != nil {
		return Check{Name: "server configuration", Status: Warn, Detail: err.Error()}
	}

	plan, err := seed.Plan(ctx, opts.Store, found)
	if err != nil {
		return Check{Name: "server configuration", Status: Warn, Detail: err.Error()}
	}

	detail := fmt.Sprintf("found %d domain(s), %d mailbox(es), %d alias(es) in Postfix/Dovecot",
		len(found.Domains), len(found.Users), len(found.Aliases))
	if plan.Empty() {
		return Check{Name: "server configuration", Status: OK, Detail: detail + "; all of them are in the panel"}
	}
	return Check{
		Name:   "server configuration",
		Status: Warn,
		Detail: fmt.Sprintf("%s; %s not in the panel, and the next sync would drop %s",
			detail,
			plural(plan.Total(), "1 entry is", fmt.Sprintf("%d entries are", plan.Total())),
			plural(plan.Total(), "it", "them")),
		Hint:    "import them instead of recreating them by hand",
		Command: "mailx-admin adopt",
	}
}

func serviceCheck(ctx context.Context, opts Options) Check {
	if opts.SkipServices {
		return Check{}
	}

	if _, err := exec.LookPath("systemctl"); err != nil {
		return Check{
			Name:   "services",
			Status: Warn,
			Detail: "systemctl is not available on this host",
			Hint:   "run doctor on the mail server itself",
		}
	}

	var inactive []string
	for _, n := range []string{"postfix", "dovecot", "opendkim"} {
		out, err := execx.Output(ctx, 10*time.Second, "systemctl", "is-active", n)
		state := strings.TrimSpace(string(out))
		if err != nil || state != "active" {
			inactive = append(inactive, n+": "+state)
		}
	}
	if len(inactive) > 0 {
		return Check{
			Name:    "services",
			Status:  Fail,
			Detail:  strings.Join(inactive, ", "),
			Hint:    "the configuration cannot take effect while a daemon is down",
			Command: "systemctl status postfix dovecot opendkim",
		}
	}
	return Check{Name: "services", Status: OK, Detail: "postfix, dovecot and opendkim are active"}
}

const (
	postfwdCheckName = "outgoing rate limits"
	postfwdService   = "postfwd"

	// postfwdProbeClient stands for "a mail client somewhere out there".
	// 203.0.113.0/24 is TEST-NET-3 (RFC 5737): never routed, so a probe can
	// never be confused with a real submission.
	postfwdProbeClient = "203.0.113.9"
)

// rateLimitCheck answers "is the thing I configured actually running?" for the
// per-domain outgoing rate limits.
//
// The failure it exists for is a limit that looks configured in the panel and is
// silently not enforced: the row is in the database, /etc/postfwd.cf is written,
// main.cf tells Postfix to consult it -- and postfwd is not installed, not
// running, listening elsewhere, or loaded a file whose rules never match.
// Nothing else in the panel shows that, and Postfix's DUNNO fallback means mail
// keeps flowing, so the operator's only clue is a limit that never triggers.
//
// Every step below is a different way for that to happen, cheapest first: the
// binary, the service, the Postfix hook, the reload flags, the file on disk, and
// finally the running daemon itself -- asked the same questions its rules answer
// (see postfwdProbeCheck).
func rateLimitCheck(ctx context.Context, opts Options) Check {
	if opts.Store == nil {
		return Check{}
	}

	snap, err := opts.Store.Snapshot(ctx)
	if err != nil {
		return Check{Name: postfwdCheckName, Status: Warn, Detail: "the configured limits could not be read: " + err.Error()}
	}

	var limited []models.Domain
	var described []string
	for _, d := range snap.Domains {
		if !d.Active || !d.RateLimited() {
			continue
		}
		limited = append(limited, d)
		described = append(described, fmt.Sprintf("%s (%s)", d.Name, rateLimitWindows(d)))
	}
	if len(limited) == 0 {
		return Check{Name: postfwdCheckName, Status: Info, Detail: "no domain has an outgoing rate limit"}
	}
	sort.Strings(described)
	detail := fmt.Sprintf("%d domain(s): %s", len(limited), firstFew(described, 4))

	if opts.SkipServices {
		return Check{Name: postfwdCheckName, Status: Info, Detail: detail}
	}

	bin, ok := postfwdBinary()
	if !ok {
		return Check{
			Name:    postfwdCheckName,
			Status:  Warn,
			Detail:  detail + ", but postfwd is not installed",
			Hint:    "the limits are written and Postfix asks for them, but nothing answers: install postfwd (re-running the installer does it)",
			Command: "apt-get install postfwd",
		}
	}

	if out, err := execx.Output(ctx, 10*time.Second, "systemctl", "is-active", postfwdService); err != nil || strings.TrimSpace(string(out)) != "active" {
		return Check{
			Name:    postfwdCheckName,
			Status:  Warn,
			Detail:  detail + ", but the postfwd service is " + strings.TrimSpace(string(out)),
			Hint:    "Postfix falls back to DUNNO, so mail flows and nothing is limited; journalctl -u postfwd says why",
			Command: "systemctl status postfwd",
		}
	}

	if opts.Config == nil {
		return Check{Name: postfwdCheckName, Status: Info, Detail: detail + "; not verified (no mail configuration in this run)"}
	}

	// Postfix is configured to ask for a policy decision only when a limit
	// exists; a main.cf without that hook means the sync never ran.
	mainCF := filepath.Join(opts.Config.Mail.PostfixConfDir, "main.cf")
	if src, err := os.ReadFile(mainCF); err != nil {
		return Check{
			Name:   postfwdCheckName,
			Status: Warn,
			Detail: detail + ", but " + mainCF + " could not be read: " + err.Error(),
		}
	} else if !strings.Contains(string(src), "check_policy_service inet:"+postfwd.PolicyAddr) {
		return Check{
			Name:    postfwdCheckName,
			Status:  Warn,
			Detail:  detail + ", and postfwd is running, but " + mainCF + " never asks it",
			Hint:    "the queue accepts mail without consulting the limits; run `mailx-admin sync` to render main.cf",
			Command: "mailx-admin sync",
		}
	}

	// --keep_rates is what keeps a counter across the reload the panel triggers
	// on every config change. Without it each sync hands out a fresh allowance,
	// which for a daily cap is the same as no cap at all.
	if out, err := execx.Output(ctx, 10*time.Second, "systemctl", "show", "-p", "ExecStart", "--value", postfwdService); err == nil &&
		strings.TrimSpace(string(out)) != "" && !strings.Contains(string(out), "keep_rates") {
		return Check{
			Name:    postfwdCheckName,
			Status:  Warn,
			Detail:  detail + ", but postfwd runs without --keep_rates, so every reload resets the counters",
			Hint:    "a daily cap that restarts at each sync is not a daily cap; re-run the installer to rewrite the unit",
			Command: "systemctl cat postfwd",
		}
	}

	return postfwdConfigChecks(ctx, opts, snap, limited, detail, bin)
}

// postfwdConfigChecks covers the two things left once the daemon is up: the file
// it is reading (is it the one the panel would render, and does postfwd's own
// parser accept it) and what the daemon does with a message (postfwdProbeCheck).
func postfwdConfigChecks(ctx context.Context, opts Options, snap *models.Snapshot, limited []models.Domain, detail, bin string) Check {
	conf := postfwdConfPath(opts)

	src, err := os.ReadFile(conf)
	if err != nil {
		return Check{
			Name:    postfwdCheckName,
			Status:  Warn,
			Detail:  detail + ", but " + conf + " could not be read: " + err.Error(),
			Hint:    "postfwd was started without the panel's rules; run `mailx-admin sync` to render them",
			Command: "mailx-admin sync",
		}
	}

	// The file on disk is the last thing a sync wrote, not the state of the
	// database. Comparing them is the only way to tell "the limit was saved" from
	// "the limit reached the daemon".
	if want := string(reconciler.RenderPostfwdConf(snap.Domains)); want != string(src) {
		return Check{
			Name:    postfwdCheckName,
			Status:  Warn,
			Detail:  detail + ", but " + conf + " is not what the panel would render",
			Hint:    "the saved limits have not reached postfwd (a failed or never-run sync does this); check the last sync below",
			Command: "mailx-admin sync",
		}
	}

	// postfwd's own parser is the authority on the rendered rules. A rule it
	// rejects is one Postfix asks about and postfwd answers DUNNO to, which is
	// a limit that reads as configured and enforces nothing. `-C` parses the
	// file and exits without touching the running daemon.
	if out, err := execx.Output(ctx, 20*time.Second, bin, "-C", "-f", conf); err != nil {
		return Check{
			Name:    postfwdCheckName,
			Status:  Warn,
			Detail:  detail + ", but " + bin + " rejects " + conf + ": " + firstLine(string(out)),
			Hint:    "a rule postfwd cannot parse is a rule it does not enforce; the file is rendered by the last sync",
			Command: bin + " -C -f " + conf,
		}
	}

	return postfwdProbeCheck(ctx, limited[0], conf, detail)
}

// postfwdPathProbe is one probe: the request to send, and the wording for when
// the answer is not the one the probe rule gives.
type postfwdPathProbe struct {
	req     postfwd.Request
	problem string
	hint    string
}

// postfwdProbeCheck asks the running daemon what it would do -- the step that
// makes "the limit is configured" and "the limit is enforced" two different
// claims.
//
// Four questions, each aimed at a failure that is invisible from the outside:
//
//  1. The canary sender. Anything but the canary's own reply means the daemon is
//     running some other file (never reloaded, started with --file elsewhere,
//     or it rejected the file at load time).
//  2. A message from this host (127.0.0.1, no SASL): the webmail path. A rule
//     that only matched authenticated submissions would answer DUNNO to exactly
//     the mail the cap exists for, and this is the probe that notices.
//  3. A message from an authenticated client elsewhere: the rule a 587/465
//     client hits.
//  4. The rate canary (postfwdRateCanary): "do the caps count at all?". The
//     first three only prove a message *matches* the file -- none of them
//     reaches a rate() action, so a file whose rate() rules count nothing
//     answers all three correctly.
//
// The probe rules sit ahead of the rate rules, so none of this touches a
// customer's counter and none of it can exhaust an allowance; the rate canary
// has a bucket of its own.
func postfwdProbeCheck(ctx context.Context, d models.Domain, conf, detail string) Check {
	const recipient = "postmaster@example.net"

	canary := postfwd.Request{
		Sender:        postfwd.CanarySender,
		Recipient:     recipient,
		ClientAddress: postfwdProbeClient,
		QueueID:       "MAILXDOCTOR",
	}
	resp, err := postfwd.Ask(ctx, postfwd.PolicyAddr, canary)
	if err != nil {
		return Check{
			Name:    postfwdCheckName,
			Status:  Warn,
			Detail:  detail + ", but nothing answered on " + postfwd.PolicyAddr + ": " + err.Error(),
			Hint:    "Postfix accepts everything when its policy server is silent, so the limits do nothing; systemctl status postfwd says why",
			Command: "systemctl status postfwd",
		}
	}
	if resp.Action != postfwd.CanaryReply {
		return Check{
			Name:    postfwdCheckName,
			Status:  Warn,
			Detail:  fmt.Sprintf("%s, but postfwd answered %q to its canary rule instead of %q", detail, resp.Action, postfwd.CanaryReply),
			Hint:    "the daemon is not running the file the panel wrote; reloading it makes it read " + conf,
			Command: "systemctl reload postfwd",
		}
	}

	probes := []postfwdPathProbe{
		{
			req: postfwd.Request{
				Sender:        postfwd.ProbeSender(d.Name),
				Recipient:     recipient,
				ClientAddress: "127.0.0.1",
				QueueID:       "MAILXDOCTOR",
			},
			problem: "a submission from this host for " + d.Name + " does not match its rules",
			hint:    "webmail and the panel's own mail submit through 127.0.0.1 without SASL; the rules have to cover that path or the cap only ever applies to mail clients",
		},
		{
			req: postfwd.Request{
				Sender:        postfwd.ProbeSender(d.Name),
				Recipient:     recipient,
				ClientAddress: postfwdProbeClient,
				SASLUsername:  "mailx-doctor",
				SASLMethod:    "plain",
				QueueID:       "MAILXDOCTOR",
			},
			problem: "an authenticated submission from another host for " + d.Name + " does not match its rules",
			hint:    "the authenticated rule combines sasl_username=~.+ with a client_address pattern; check it in " + conf,
		},
	}
	for _, p := range probes {
		if c := postfwdExpect(ctx, p, postfwd.ProbeReply, conf, detail); c.Name != "" {
			return c
		}
	}

	if c := postfwdRateCanary(ctx, recipient, conf, detail); c.Name != "" {
		return c
	}

	return Check{
		Name:   postfwdCheckName,
		Status: OK,
		Detail: detail + ", enforced by postfwd (both submission paths answered, and rate() counted)",
	}
}

// postfwdExpect sends one probe and reports a Check when the answer is not the
// probe rule's own reply.
func postfwdExpect(ctx context.Context, p postfwdPathProbe, want, conf, detail string) Check {
	resp, err := postfwd.Ask(ctx, postfwd.PolicyAddr, p.req)
	if err != nil {
		return Check{
			Name:    postfwdCheckName,
			Status:  Warn,
			Detail:  detail + ", but the probe for " + p.req.Sender + " failed: " + err.Error(),
			Hint:    "systemctl status postfwd; the rules it loaded are in " + conf,
			Command: "systemctl status postfwd",
		}
	}
	if resp.Action != want {
		return Check{
			Name:    postfwdCheckName,
			Status:  Warn,
			Detail:  fmt.Sprintf("%s, but %s: postfwd answered %q where %q was expected", detail, p.problem, resp.Action, want),
			Hint:    p.hint,
			Command: "mailx-admin sync",
		}
	}
	return Check{}
}

// maxRateCanaryAsks bounds how often postfwdRateCanary asks. The canary rule
// allows one message a minute, so a run inside a fresh window needs two asks --
// the allowed one, then the refusal. The third is slack for a window that
// happens to expire between two asks; it costs one more request and nothing
// else.
const maxRateCanaryAsks = 3

// postfwdRateCanary asks the running daemon the one question a reject rule
// cannot answer: does rate() count?
//
// That is the question the last release got wrong. postfwd counts nothing unless
// the first argument of rate() names one of its request items -- it evaluates
// `if (defined $request->{$item})` around the whole counting block, bucket
// creation included -- so a rule keyed on a name of the panel's own invention is
// written, parsed, loaded, and silently answers DUNNO to every message. The
// probes above cannot see that: they are plain reject rules and never reach a
// rate().
//
// The canary rule in the rendered file is `rate(sender/1/60/<reply>)`, keyed on a
// sender reserved by RFC 2606, so the first message inside a window is allowed
// and the next is refused -- and a refusal is the proof that a counter was kept.
// Starting from a fresh window the doctor therefore has to ask twice. Any
// refusal counts, so the check does not depend on whether postfwd charges the
// message it allows or the one it refuses.
func postfwdRateCanary(ctx context.Context, recipient, conf, detail string) Check {
	req := postfwd.Request{
		Sender:        postfwd.RateCanarySender,
		Recipient:     recipient,
		ClientAddress: postfwdProbeClient,
		QueueID:       "MAILXDOCTOR",
	}

	answers := make([]string, 0, maxRateCanaryAsks)
	for i := 0; i < maxRateCanaryAsks; i++ {
		resp, err := postfwd.Ask(ctx, postfwd.PolicyAddr, req)
		if err != nil {
			return Check{
				Name:    postfwdCheckName,
				Status:  Warn,
				Detail:  detail + ", but the rate() canary failed: " + err.Error(),
				Hint:    "systemctl status postfwd; the rules it loaded are in " + conf,
				Command: "systemctl status postfwd",
			}
		}
		answers = append(answers, resp.Action)
		if resp.Action == postfwd.RateCanaryReply {
			break
		}
	}

	return rateCanaryVerdict(answers, conf, detail)
}

// rateCanaryVerdict is the decision half of postfwdRateCanary, kept pure so its
// wording and its tolerance can be tested without a daemon.
//
// Three DUNNOs mean the file is loaded and matching (the probes proved that) but
// rate() is not counting, which is exactly the state in which a cap reads as
// configured and enforces nothing -- a state that lasted a whole release.
func rateCanaryVerdict(answers []string, conf, detail string) Check {
	for _, a := range answers {
		if a == postfwd.RateCanaryReply {
			return Check{}
		}
	}

	return Check{
		Name:   postfwdCheckName,
		Status: Warn,
		Detail: fmt.Sprintf("%s, but postfwd never refused the rate() canary (answers: %q), so the caps count nothing", detail, answers),
		Hint: "postfwd skips its whole counting block unless the first argument of rate() is one of its request items " +
			"(`if (defined $request{$item})`); the rules in " + conf + " must key rate() on sender_domain, and " +
			"`mailx-admin sync` renders them that way",
		Command: "mailx-admin sync",
	}
}

// postfwdBinary finds the daemon's executable.
//
// The Debian package is called postfwd and ships /usr/sbin/postfwd, but postfwd2
// is the name the upstream tarball (and some distributions) use, and a panel
// that only looked for one of them reported "not installed" while the daemon was
// running.
func postfwdBinary() (string, bool) {
	for _, name := range []string{"postfwd", "postfwd2"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, true
		}
	}
	for _, path := range []string{"/usr/sbin/postfwd", "/usr/local/sbin/postfwd", "/usr/sbin/postfwd2", "/usr/local/sbin/postfwd2"} {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path, true
		}
	}
	return "", false
}

// postfwdConfPath is the file the installer and the reconciler use:
// /etc/postfwd.cf next to the Postfix configuration directory.
func postfwdConfPath(opts Options) string {
	return filepath.Join(filepath.Dir(opts.Config.Mail.PostfixConfDir), "postfwd.cf")
}

// rateLimitWindows names the caps a domain has, so a check about "example.com"
// says which windows are configured instead of only the first one.
func rateLimitWindows(d models.Domain) string {
	var parts []string
	if d.OutboundRateLimit > 0 {
		parts = append(parts, fmt.Sprintf("%d/h", d.OutboundRateLimit))
	}
	if d.OutboundRateDaily > 0 {
		parts = append(parts, fmt.Sprintf("%d/d", d.OutboundRateDaily))
	}
	if d.OutboundRateMonthly > 0 {
		parts = append(parts, fmt.Sprintf("%d/mo", d.OutboundRateMonthly))
	}
	if d.OutboundRateBurst > 0 {
		parts = append(parts, fmt.Sprintf("burst %d/min", d.OutboundRateBurst))
	}
	return strings.Join(parts, " ")
}

// firstLine keeps a command's complaint to one line, so a parser error does not
// turn a doctor check into a wall of text.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if s == "" {
		return "(no output)"
	}
	return s
}

// lastSyncCheck reports what the panel's own sync history says, which is the
// first thing to look at when "the panel did nothing" after a change.
func lastSyncCheck(ctx context.Context, opts Options) Check {
	if opts.LastSync == nil {
		return Check{}
	}
	s := opts.LastSync

	switch s.Status {
	case "ok":
		return Check{
			Name:   "last sync",
			Status: OK,
			Detail: fmt.Sprintf("%s (%s), no errors", s.StartedAt.Format(time.RFC1123), s.Trigger),
		}
	case "running":
		return Check{
			Name:   "last sync",
			Status: Info,
			Detail: fmt.Sprintf("still running, started %s (%s)", s.StartedAt.Format(time.RFC1123), s.Trigger),
		}
	default:
		return Check{
			Name:    "last sync",
			Status:  Fail,
			Detail:  fmt.Sprintf("failed at %s (%s): %s", s.StartedAt.Format(time.RFC1123), s.Trigger, s.Error),
			Hint:    "the panel's changes are in the database but may not have reached the daemons",
			Command: "systemctl status mailx-admin",
		}
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
