package mutations

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/reconciler"
	"github.com/gtmylab/mailx-admin/internal/store"
)

// TestCreateDomainCreatesPostmasterMailbox is the contract behind the DMARC
// record: the panel publishes rua=mailto:postmaster@<domain> (see
// internal/dns.BuildPlan), so creating a domain has to create that address.
//
// Before this, a fresh domain had no postmaster mailbox and no admin@ mailbox
// either -- every aggregate report a receiver sent bounced, and the operator saw
// a DMARC policy that was being evaluated with no way to read the result.
func TestCreateDomainCreatesPostmasterMailbox(t *testing.T) {
	svc, database, conf := sqliteTestService(t)
	ctx := context.Background()

	res, err := svc.CreateDomain(ctx, Actor{Name: "cli:test"}, CreateDomainInput{Name: "Example.Test"})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	var username, email, hash string
	var quota, active, isAdmin int
	err = database.QueryRowContext(ctx, `
		SELECT username, email, password_hash, quota_mb, active, is_admin
		FROM users WHERE email = 'postmaster@example.test'
	`).Scan(&username, &email, &hash, &quota, &active, &isAdmin)
	if err != nil {
		t.Fatalf("no postmaster mailbox was created with the domain: %v", err)
	}
	if username != "postmaster" {
		t.Errorf("username = %q, want %q", username, "postmaster")
	}
	// A 0 quota is not "unlimited" here: it is rendered into the passdb as
	// storage=0M, which bounces every report the mailbox exists for.
	if quota != postmasterQuotaMB || quota <= 0 {
		t.Errorf("quota_mb = %d, want %d", quota, postmasterQuotaMB)
	}
	if active != 1 || isAdmin != 0 {
		t.Errorf("active/is_admin = %d/%d, want 1/0", active, isAdmin)
	}
	// A hash that is not a Dovecot hash would make the row undeliverable the
	// moment somebody set a password on it; the preview placeholder would mean
	// a dry run leaked into the real table.
	if !strings.HasPrefix(hash, "{") || hash == postmasterPreviewHash {
		t.Errorf("password_hash = %q, want a real Dovecot hash", hash)
	}

	// The row alone is not deliverability: the reconciler has to have written
	// it into the passwd-file every Dovecot protocol reads.
	passwd, err := os.ReadFile(filepath.Join(conf, "dovecot", "users"))
	if err != nil {
		t.Fatalf("read dovecot passwd file: %v", err)
	}
	if !strings.Contains(string(passwd), "postmaster@example.test") {
		t.Errorf("postmaster@example.test is missing from the rendered passwd file:\n%s", passwd)
	}

	// An operator who does not know about the mailbox will wonder where it came
	// from, or delete it and lose the reports silently.
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "postmaster@example.test") {
		t.Errorf("warnings = %q, want one mentioning postmaster@example.test", res.Warnings)
	}
}

// TestValidateRateLimit pins the rules the form and the CLI share. The one that
// matters most is "a burst allowance needs an hourly limit": without it the
// panel would happily store a row that reads as limited and behaves as
// "Burst messages per minute, forever".
func TestValidateRateLimit(t *testing.T) {
	cases := []struct {
		name       string
		in         SetDomainRateLimitInput
		ok         bool
		wantAction string
	}{
		{"hourly limit only", SetDomainRateLimitInput{PerHour: 500}, true, models.RateActionDefer},
		{"action is normalized", SetDomainRateLimitInput{PerHour: 500, Action: " REJECT "}, true, models.RateActionReject},
		{"no limit at all", SetDomainRateLimitInput{}, true, models.RateActionDefer},
		{"burst with a limit", SetDomainRateLimitInput{PerHour: 500, Burst: 50}, true, models.RateActionDefer},
		{"negative limit", SetDomainRateLimitInput{PerHour: -1}, false, ""},
		{"limit above the ceiling", SetDomainRateLimitInput{PerHour: rateLimitMaxPerHour + 1}, false, ""},
		{"burst above the ceiling", SetDomainRateLimitInput{PerHour: 10, Burst: rateLimitMaxBurst + 1}, false, ""},
		{"burst without a limit", SetDomainRateLimitInput{Burst: 10}, false, ""},
		{"unknown action", SetDomainRateLimitInput{PerHour: 10, Action: "drop"}, false, ""},

		// The day and month windows. Each can stand alone, and a shorter window
		// may never allow less than a longer one -- that pair renders two rules
		// where one can never fire, and the UI would show a cap that is a lie.
		{"daily only", SetDomainRateLimitInput{PerDay: 4000}, true, models.RateActionDefer},
		{"monthly only", SetDomainRateLimitInput{PerMonth: 60000}, true, models.RateActionDefer},
		{"all three windows", SetDomainRateLimitInput{PerHour: 500, PerDay: 4000, PerMonth: 60000}, true, models.RateActionDefer},
		{"burst with a daily cap", SetDomainRateLimitInput{PerDay: 4000, Burst: 50}, true, models.RateActionDefer},
		{"negative daily cap", SetDomainRateLimitInput{PerDay: -1}, false, ""},
		{"daily above the ceiling", SetDomainRateLimitInput{PerDay: rateLimitMaxPerDay + 1}, false, ""},
		{"monthly above the ceiling", SetDomainRateLimitInput{PerMonth: rateLimitMaxPerMonth + 1}, false, ""},
		{"daily below the hourly cap", SetDomainRateLimitInput{PerHour: 500, PerDay: 100}, false, ""},
		{"monthly below the daily cap", SetDomainRateLimitInput{PerDay: 4000, PerMonth: 1000}, false, ""},
		{"monthly below the hourly cap", SetDomainRateLimitInput{PerHour: 5000, PerMonth: 1000}, false, ""},
	}

	for _, c := range cases {
		err := validateRateLimit(&c.in)
		if (err == nil) != c.ok {
			t.Errorf("%s: validateRateLimit = %v, want ok=%v", c.name, err, c.ok)
			continue
		}
		if c.ok && c.in.Action != c.wantAction {
			t.Errorf("%s: action = %q, want %q", c.name, c.in.Action, c.wantAction)
		}
	}
}

// TestSetDomainRateLimitReachesThePostfwdConfig follows the limit from the
// mutation to the file postfwd reads: the row is only half of it, and a limit
// that never reaches /etc/postfwd.cf is a limit the operator believes in and
// nothing enforces.
func TestSetDomainRateLimitReachesThePostfwdConfig(t *testing.T) {
	svc, database, _ := sqliteTestService(t)
	ctx := context.Background()

	if _, err := svc.CreateDomain(ctx, Actor{Name: "cli:test"}, CreateDomainInput{Name: "bulk.test"}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	var id int64
	if err := database.QueryRow(`SELECT id FROM domains WHERE name = 'bulk.test'`).Scan(&id); err != nil {
		t.Fatalf("read domain id: %v", err)
	}

	if _, err := svc.SetDomainRateLimit(ctx, Actor{Name: "cli:test"}, SetDomainRateLimitInput{
		DomainID: id, PerHour: 250, PerDay: 1000, PerMonth: 20000, Burst: 25,
		Action: models.RateActionReject,
	}); err != nil {
		t.Fatalf("SetDomainRateLimit: %v", err)
	}

	snap, err := store.New(database).Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	var got *models.Domain
	for i := range snap.Domains {
		if snap.Domains[i].ID == id {
			got = &snap.Domains[i]
		}
	}
	if got == nil {
		t.Fatal("the domain is missing from the snapshot the reconciler renders")
	}
	if got.OutboundRateLimit != 250 || got.OutboundRateDaily != 1000 ||
		got.OutboundRateMonthly != 20000 || got.OutboundRateBurst != 25 ||
		got.RateAction() != models.RateActionReject {
		t.Fatalf("stored caps = %d/h %d/d %d/mo burst %d action %q",
			got.OutboundRateLimit, got.OutboundRateDaily, got.OutboundRateMonthly,
			got.OutboundRateBurst, got.RateAction())
	}

	conf := string(reconciler.RenderPostfwdConf(snap.Domains))
	rule := fmt.Sprintf("RL_%04d", id)
	for _, want := range []string{
		"sender_domain==bulk.test",
		"id=" + rule + "_H",
		"id=" + rule + "_D",
		"id=" + rule + "_M",
		"id=" + rule + "_BURST",
		"action=rate(sender_domain/250/3600/554 5.7.1",
		"action=rate(sender_domain/1000/86400/554 5.7.1",
		"action=rate(sender_domain/20000/2592000/554 5.7.1",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("postfwd config is missing %q:\n%s", want, conf)
		}
	}
}

// TestSetDomainRateLimitRejectsAnUnknownDomain keeps the mutation from reporting
// success for a domain that does not exist (the UPDATE would affect no rows).
func TestSetDomainRateLimitRejectsAnUnknownDomain(t *testing.T) {
	svc, _, _ := sqliteTestService(t)

	_, err := svc.SetDomainRateLimit(context.Background(), Actor{Name: "cli:test"},
		SetDomainRateLimitInput{DomainID: 4242, PerHour: 10})
	if err == nil {
		t.Fatal("SetDomainRateLimit accepted an unknown domain")
	}
}

// TestPostmasterPasswordIsRandom makes sure the mailbox is not created with a
// known or empty password: the address is a public one (it is in the DMARC
// record), so a predictable credential would be an open relay into a mailbox.
func TestPostmasterPasswordIsRandom(t *testing.T) {
	svc, _, _ := sqliteTestService(t)
	ctx := context.Background()

	first, err := svc.postmasterPasswordHash(ctx)
	if err != nil {
		t.Fatalf("postmasterPasswordHash: %v", err)
	}
	second, err := svc.postmasterPasswordHash(ctx)
	if err != nil {
		t.Fatalf("postmasterPasswordHash: %v", err)
	}
	if first == second {
		t.Fatal("two postmaster passwords hashed to the same value")
	}
	if !strings.HasPrefix(first, "{") {
		t.Fatalf("hash %q is not in Dovecot format", first)
	}
}
