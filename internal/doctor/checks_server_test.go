package doctor

import (
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/postfwd"
)

// TestRateCanaryVerdict is the unit test for the check that would have caught
// v1.6.38: the rendered rate() rules named their bucket with a rule id, postfwd
// counted nothing because that name is not a request item, and every cap stayed
// unfired -- while the canary and both path probes answered correctly, so the
// doctor reported the limits enforced.
//
// The verdict has to read "refused at least once" as proof and everything else as
// a warning. The canary allows one message per window, so a run right after
// another one sees the refusal first, a run in a fresh window sees the allowed
// message first, and a run that straddles a window boundary needs a third ask.
func TestRateCanaryVerdict(t *testing.T) {
	const (
		conf   = "/etc/postfwd.cf"
		detail = `domain "example.com" has 500/hour`
	)

	tests := []struct {
		name    string
		answers []string
		ok      bool
	}{
		{"allowed, then refused", []string{"dunno", postfwd.RateCanaryReply}, true},
		{"refused immediately (counter kept from an earlier run)", []string{postfwd.RateCanaryReply}, true},
		{"refused on the third ask (window expired in between)", []string{"dunno", "dunno", postfwd.RateCanaryReply}, true},
		{"never refused, so rate() counted nothing", []string{"dunno", "dunno", "dunno"}, false},
		{"some other reply is not a refusal", []string{"dunno", "554 5.7.1 our own probe"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rateCanaryVerdict(tt.answers, conf, detail)

			if tt.ok {
				if got.Name != "" || got.Status != "" {
					t.Fatalf("a counting rate canary produced a finding: %+v", got)
				}
				return
			}

			if got.Name != postfwdCheckName {
				t.Errorf("check name = %q, want %q", got.Name, postfwdCheckName)
			}
			if got.Status != Warn {
				t.Errorf("status = %q, want %q: a cap that counts nothing must not read as healthy", got.Status, Warn)
			}
			if !strings.Contains(got.Detail, detail) {
				t.Errorf("detail drops the context it was given: %q", got.Detail)
			}
			if !strings.Contains(got.Detail, "count nothing") {
				t.Errorf("detail does not say what is wrong: %q", got.Detail)
			}
			// The operator needs the cause, not only the symptom, and the command
			// that re-renders the rules.
			if !strings.Contains(got.Hint, "sender_domain") || !strings.Contains(got.Hint, "$request{$item}") {
				t.Errorf("hint does not name the cause: %q", got.Hint)
			}
			if !strings.Contains(got.Hint, conf) {
				t.Errorf("hint does not say which file is wrong: %q", got.Hint)
			}
			if got.Command != "mailx-admin reconcile" {
				t.Errorf("command = %q, want the reconcile that re-renders the rules", got.Command)
			}
		})
	}
}

// TestFirstFileDifference pins the detail that turns "the file is not what the
// panel would render" into something an operator can act on.
//
// The report that prompted it was a host whose /etc/postfwd.cf still carried the
// v1.6.38 rules: the doctor said the file was wrong and stopped there, so the one
// line that explained everything -- rate() keyed on a rule id instead of a
// postfwd request item -- never appeared on the screen. The two fixtures below
// are those two renders, header and all.
func TestFirstFileDifference(t *testing.T) {
	lines := func(l ...string) string { return strings.Join(l, "\n") + "\n" }

	stale := lines(
		"# Managed by mailx-admin -- DO NOT EDIT",
		"# Windows are rolling (3600/86400/2592000s); the key is the rule id and",
		"# --keep_rates keeps counters across reloads.",
		"",
		"id=MAILX_CANARY; sender==canary@mailx.invalid; action=554 5.7.1 mailx-admin doctor canary",
		"",
		"id=RL_0001_D",
		"  sender_domain==example.com",
		"  action=rate(RL_0001_D/2/86400/450 4.7.1 Rate limit exceeded for example.com: 2 messages per day. Try again later.)",
		"",
		"# Everything else: no policy from postfwd.",
		"id=DEFAULT; action=dunno",
	)
	fresh := lines(
		"# Managed by mailx-admin -- DO NOT EDIT",
		"# Windows are rolling (3600/86400/2592000s). rate() is keyed on the",
		"# sender domain -- postfwd counts nothing when its first argument is not",
		"# one of its request items -- and the bucket is the rule id.",
		"",
		"id=MAILX_CANARY; sender==canary@mailx.invalid; action=554 5.7.1 mailx-admin doctor canary",
		"",
		"id=RL_0001_D",
		"  sender_domain==example.com",
		"  action=rate(sender_domain/2/86400/450 4.7.1 Rate limit exceeded for example.com: 2 messages per day. Try again later.)",
		"",
		"# Everything else: no policy from postfwd.",
		"id=DEFAULT; action=dunno",
	)

	t.Run("the stale v1.6.38 rule is quoted next to the expected one", func(t *testing.T) {
		got := firstFileDifference(stale, fresh)

		// The reworded header must not be what gets reported: it is the comment
		// block that changed, and the operator needs the rule.
		for _, want := range []string{
			"line 9 on disk is",
			`action=rate(RL_0001_D/2/86400/450`,
			`action=rate(sender_domain/2/86400/450`,
			"line 10 of the render",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("difference does not mention %q:\n%s", want, got)
			}
		}
		if strings.Contains(got, "Managed by mailx-admin") || strings.Contains(got, "Windows are rolling") {
			t.Errorf("difference reports the comment header instead of the rule:\n%s", got)
		}
	})

	t.Run("a file missing a rule names the rule the render adds", func(t *testing.T) {
		truncated := lines(
			"# Managed by mailx-admin -- DO NOT EDIT",
			"",
			"id=MAILX_CANARY; sender==canary@mailx.invalid; action=554 5.7.1 mailx-admin doctor canary",
			"",
			"# Everything else: no policy from postfwd.",
			"id=DEFAULT; action=dunno",
		)

		got := firstFileDifference(truncated, fresh)
		for _, want := range []string{"the render adds", "id=RL_0001_D", "which the file does not have"} {
			if !strings.Contains(got, want) {
				t.Errorf("difference does not mention %q:\n%s", want, got)
			}
		}
	})

	t.Run("a rule the panel dropped is named as such", func(t *testing.T) {
		extra := strings.Replace(stale, "id=DEFAULT; action=dunno",
			"id=RL_0009_H\n  sender_domain==old.example\n  action=rate(RL_0009_H/5/3600/450 4.7.1 gone)\n\nid=DEFAULT; action=dunno", 1)

		got := firstFileDifference(extra, stale)
		for _, want := range []string{"line 12 on disk is", "id=RL_0009_H", "which the panel no longer renders"} {
			if !strings.Contains(got, want) {
				t.Errorf("difference does not mention %q:\n%s", want, got)
			}
		}
	})

	t.Run("only a comment differs", func(t *testing.T) {
		reworded := strings.Replace(stale, "# --keep_rates keeps counters across reloads.",
			"# --keep_rates keeps counters across reloads, and a reload is a sync.", 1)

		got := firstFileDifference(reworded, stale)
		if !strings.Contains(got, "line 3 differs") || !strings.Contains(got, "reload is a sync") {
			t.Errorf("a comment-only difference is not reported:\n%s", got)
		}
	})

	t.Run("a CRLF file is not a rule difference", func(t *testing.T) {
		got := firstFileDifference(strings.ReplaceAll(stale, "\n", "\r\n"), stale)
		if strings.Contains(got, "rate(") {
			t.Errorf("CRLF endings were reported as a rule difference:\n%s", got)
		}
	})

	t.Run("one absurd line cannot bury the finding", func(t *testing.T) {
		long := strings.Replace(stale, "action=rate(RL_0001_D", "action=rate(RL_0001_D; "+strings.Repeat("x", 400), 1)
		if got := firstFileDifference(long, fresh); len(got) > 400 {
			t.Errorf("detail is %d characters long, want it clipped:\n%s", len(got), got)
		}
	})
}
