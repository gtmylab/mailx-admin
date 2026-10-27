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
			if got.Command != "mailx-admin sync" {
				t.Errorf("command = %q, want the sync that re-renders the rules", got.Command)
			}
		})
	}
}
