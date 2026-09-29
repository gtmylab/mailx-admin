package dns

import (
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

func testDomain() models.Domain {
	return models.Domain{
		ID: 1, Name: "example.com", IsPrimary: true, Active: true,
		DKIMSelector:       "default",
		DKIMPrivateKeyPath: "/etc/opendkim/keys/example.com/default.private",
		DKIMPublicRecord:   "v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkq",
	}
}

// TestBuildPlanHasEverythingMailNeeds — the page, the export and the check all
// render this one list, so what it contains is the contract.
func TestBuildPlanHasEverythingMailNeeds(t *testing.T) {
	plan := BuildPlan(testDomain(), "203.0.113.10", "mail.example.com")

	want := map[string]string{
		"A|example.com":                      "203.0.113.10",
		"A|mail.example.com":                 "203.0.113.10",
		"MX|example.com":                     "mail.example.com",
		"TXT|example.com":                    "v=spf1 mx a ip4:203.0.113.10 ~all",
		"TXT|default._domainkey.example.com": "v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkq",
		"TXT|_dmarc.example.com":             "v=DMARC1; p=none; rua=mailto:postmaster@example.com",
		"PTR|10.113.0.203.in-addr.arpa":      "mail.example.com",
		"A|admin.example.com":                "203.0.113.10",
	}

	for _, rec := range plan.Records {
		if rec.Later {
			continue // the "add later" records are not part of the mail-flow contract
		}
		key := string(rec.Type) + "|" + rec.Name
		wantValue, ok := want[key]
		if !ok {
			t.Errorf("unexpected record %s (%s)", key, rec.Purpose)
			continue
		}
		if rec.Value != wantValue {
			t.Errorf("%s value = %q, want %q", key, rec.Value, wantValue)
		}
		delete(want, key)
	}
	if len(want) > 0 {
		t.Errorf("plan is missing %v", want)
	}

	// The PTR row is the one an operator cannot create themselves.
	for _, rec := range plan.Records {
		if rec.Type == TypePTR && !rec.Manual {
			t.Error("the PTR record is not marked as provider-managed")
		}
	}
}

// TestBuildPlanNeverEmitsAnEmptyIP — v1.0.4 published "A mail.example.com" with
// no address and "v=spf1 ... ip4: ~all" whenever the public-IP probe failed.
func TestBuildPlanNeverEmitsAnEmptyIP(t *testing.T) {
	plan := BuildPlan(testDomain(), "", "mail.example.com")

	if len(plan.Warnings) == 0 {
		t.Error("an unknown public IP should warn")
	}
	for _, rec := range plan.Records {
		if rec.Type == TypeA && strings.TrimSpace(rec.Value) == "" {
			t.Errorf("A record %s has an empty value", rec.Name)
		}
		if rec.Type == TypeTXT && strings.Contains(rec.Value, "ip4:") && strings.Contains(rec.Value, "ip4: ~") {
			t.Errorf("SPF record %q contains an empty ip4: mechanism", rec.Value)
		}
		// A record the checker was told to verify must carry a real value: the
		// placeholder would be queried as-is and always "differ".
		if rec.Checkable {
			if strings.TrimSpace(rec.Expected.Value) == "" || strings.Contains(rec.Expected.Value, unknownIP) {
				t.Errorf("%s is marked checkable although its expected value is a placeholder", rec.Name)
			}
		}
	}
}

// TestCheckableMatchesTheExpectedSet — BuildExpected is derived from the plan, so
// a check can never look for a record the page does not show.
func TestCheckableMatchesTheExpectedSet(t *testing.T) {
	plan := BuildPlan(testDomain(), "203.0.113.10", "mail.example.com")
	expected := BuildExpected(testDomain(), "203.0.113.10", "mail.example.com")

	if len(expected) != len(plan.Checkable()) {
		t.Fatalf("BuildExpected returned %d records, plan.Checkable %d", len(expected), len(plan.Checkable()))
	}
	if len(expected) == 0 {
		t.Fatal("no checkable records at all")
	}
	for _, e := range expected {
		if e.Name == "" || e.Value == "" {
			t.Errorf("expected record %+v is incomplete", e)
		}
	}
}

// TestReverseName — a wrong reverse name would query the wrong zone.
func TestReverseName(t *testing.T) {
	if got := reverseName("203.0.113.10"); got != "10.113.0.203.in-addr.arpa" {
		t.Errorf("reverseName = %q", got)
	}
	if got := reverseName("not-an-ip"); got != "" {
		t.Errorf("reverseName(not-an-ip) = %q, want empty", got)
	}
}

// TestSPFMustAuthoriseThisServer is the bug the old prefix match hid: an SPF
// record that merely starts with "v=spf1" was reported as correct, even when it
// did not list this server at all.
func TestSPFMustAuthoriseThisServer(t *testing.T) {
	exp := Expected{Type: TypeTXT, Name: "example.com", Value: "v=spf1 mx a ip4:203.0.113.10 ~all"}

	if ok, _ := matchRecord(exp, &Observed{Values: []string{"v=spf1 mx a ip4:203.0.113.10 ~all"}}); !ok {
		t.Error("the exact record was rejected")
	}
	if ok, _ := matchRecord(exp, &Observed{Values: []string{"v=spf1 mx a ip4:203.0.113.10 ip4:198.51.100.7 ~all"}}); !ok {
		t.Error("an SPF record with an extra sender was rejected")
	}

	ok, detail := matchRecord(exp, &Observed{Values: []string{"v=spf1 mx ~all"}})
	if ok {
		t.Error("an SPF record that does not authorise this server was accepted")
	}
	if !strings.Contains(detail, "ip4:203.0.113.10") {
		t.Errorf("detail %q does not name the missing mechanism", detail)
	}
}

// TestDKIMMustHaveTheSameKey — h= and k= may differ between providers, p= may
// not: a stale key means every signature fails.
func TestDKIMMustHaveTheSameKey(t *testing.T) {
	exp := Expected{Type: TypeTXT, Name: "default._domainkey.example.com",
		Value: "v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkq"}

	if ok, _ := matchRecord(exp, &Observed{Values: []string{"v=DKIM1; k=rsa; p=MIIBIjANBgkq"}}); !ok {
		t.Error("the same key with different tags was rejected")
	}

	ok, detail := matchRecord(exp, &Observed{Values: []string{"v=DKIM1; k=rsa; p=MIIBIjANBgkqSTALE"}})
	if ok {
		t.Error("a different public key was accepted")
	}
	if !strings.Contains(detail, "p=") {
		t.Errorf("detail %q does not point at the key", detail)
	}
}

// TestDMARCStrengthIsCompared — p=reject satisfies a p=none plan, never the
// other way round.
func TestDMARCStrengthIsCompared(t *testing.T) {
	exp := Expected{Type: TypeTXT, Name: "_dmarc.example.com", Value: "v=DMARC1; p=none"}

	cases := []struct {
		published string
		want      bool
	}{
		{"v=DMARC1; p=none; rua=mailto:admin@example.com", true},
		{"v=DMARC1; p=quarantine", true},
		{"v=DMARC1; p=reject; rua=mailto:admin@example.com", true},
		{"v=spf1 mx", false},
		{"", false},
	}
	for _, tc := range cases {
		var obs *Observed
		if tc.published != "" {
			obs = &Observed{Values: []string{tc.published}}
		}
		if ok, _ := matchRecord(exp, obs); ok != tc.want {
			t.Errorf("matchRecord(%q) = %v, want %v", tc.published, ok, tc.want)
		}
	}

	strict := Expected{Type: TypeTXT, Name: "_dmarc.example.com", Value: "v=DMARC1; p=reject"}
	ok, detail := matchRecord(strict, &Observed{Values: []string{"v=DMARC1; p=none"}})
	if ok {
		t.Error("a weaker policy than the plan was accepted")
	}
	if !strings.Contains(detail, "weaker") {
		t.Errorf("detail %q does not explain the policy difference", detail)
	}
}

// TestPTRMatchesTheMailHost — the reverse zone is where deliverability is won or
// lost, and v1.0.4 never looked at it.
func TestPTRMatchesTheMailHost(t *testing.T) {
	exp := Expected{Type: TypePTR, Name: "10.113.0.203.in-addr.arpa", Value: "mail.example.com"}

	if ok, _ := matchRecord(exp, &Observed{Values: []string{"mail.example.com"}}); !ok {
		t.Error("a matching PTR was rejected")
	}

	ok, detail := matchRecord(exp, &Observed{Values: []string{"static.203.113.10.hosting.example.net"}})
	if ok {
		t.Error("a PTR that does not name the mail host was accepted")
	}
	if !strings.Contains(detail, "mail.example.com") {
		t.Errorf("detail %q does not name the expected host", detail)
	}
}

// TestMissingRecordIsReportedAsMissing covers the "no record at all" path for
// every type, including PTR (where a missing reverse entry is common).
func TestMissingRecordIsReportedAsMissing(t *testing.T) {
	for _, exp := range []Expected{
		{Type: TypeA, Name: "example.com", Value: "203.0.113.10"},
		{Type: TypeMX, Name: "example.com", Value: "mail.example.com", Priority: 10},
		{Type: TypeTXT, Name: "example.com", Value: "v=spf1 mx ~all"},
		{Type: TypePTR, Name: "10.113.0.203.in-addr.arpa", Value: "mail.example.com"},
	} {
		ok, detail := matchRecord(exp, &Observed{})
		if ok {
			t.Errorf("%s %s matched an empty answer", exp.Type, exp.Name)
		}
		if detail == "" {
			t.Errorf("%s %s reported no reason", exp.Type, exp.Name)
		}
		if ok, _ := matchRecord(exp, nil); ok {
			t.Errorf("%s %s matched a nil observation", exp.Type, exp.Name)
		}
	}
}
