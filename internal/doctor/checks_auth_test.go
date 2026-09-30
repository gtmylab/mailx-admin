package doctor

import (
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/dovecot"
)

// TestUnverifiableHashes is the check that would have caught the failure this
// release is about: a mailbox whose hash carries a scheme the local Dovecot was
// not built with is refused at login, and nothing else in the panel can see it.
func TestUnverifiableHashes(t *testing.T) {
	// A Dovecot without libsodium, which is the host where this matters.
	withoutArgon2 := dovecot.ParseSchemes("PLAIN, CLEARTEXT, CRYPT, MD5, SHA512, SSHA512")
	withArgon2 := dovecot.ParseSchemes("PLAIN, CRYPT, SHA512, SSHA512, ARGON2I, ARGON2ID")

	cases := []struct {
		name     string
		counts   map[string]int
		schemes  dovecot.Schemes
		def      string
		wantSubs []string // every one of these must be reported
		wantNone []string // and none of these
	}{
		{
			name:     "argon2id hashes on a Dovecot without it",
			counts:   map[string]int{"ARGON2ID": 3, "CRYPT": 1},
			schemes:  withoutArgon2,
			def:      dovecot.SchemeSSHA512,
			wantSubs: []string{"3 {ARGON2ID} hash(es)"},
			wantNone: []string{"CRYPT"},
		},
		{
			name:    "the same file on a Dovecot with libsodium",
			counts:  map[string]int{"ARGON2ID": 3, "CRYPT": 1},
			schemes: withArgon2,
			def:     dovecot.SchemeArgon2id,
		},
		{
			name:     "unprefixed hashes and a passdb default that cannot be verified",
			counts:   map[string]int{"(default)": 2},
			schemes:  dovecot.ParseSchemes("PLAIN, CRYPT"),
			def:      dovecot.SchemeArgon2id,
			wantSubs: []string{"2 hash(es) with no {SCHEME}"},
		},
		{
			name:    "unprefixed hashes with a default that can be verified",
			counts:  map[string]int{"(default)": 2},
			schemes: withoutArgon2,
			def:     dovecot.SchemeSSHA512,
		},
		{
			name:   "an empty passwd-file",
			counts: map[string]int{},
			def:    dovecot.SchemeArgon2id,
		},
		{
			name:     "more than one unverifiable scheme, reported in a stable order",
			counts:   map[string]int{"ARGON2ID": 1, "BLOWFISH": 2},
			schemes:  withoutArgon2,
			def:      dovecot.SchemeSSHA512,
			wantSubs: []string{"1 {ARGON2ID} hash(es)", "2 {BLOWFISH} hash(es)"},
		},
	}

	for _, tc := range cases {
		got := unverifiableHashes(tc.counts, tc.schemes, tc.def)
		joined := strings.Join(got, ", ")

		for _, want := range tc.wantSubs {
			if !strings.Contains(joined, want) {
				t.Errorf("%s: %q not reported in %v", tc.name, want, got)
			}
		}
		for _, none := range tc.wantNone {
			if strings.Contains(joined, none) {
				t.Errorf("%s: %q must not be reported (it is verifiable): %v", tc.name, none, got)
			}
		}
		if len(tc.wantSubs) == 0 && len(got) != 0 {
			t.Errorf("%s: reported %v, want nothing", tc.name, got)
		}
	}
}

// TestFirstFew: a detail line has to stay one line, however many mailboxes are
// missing from Roundcube.
func TestFirstFew(t *testing.T) {
	if got := firstFew([]string{"a@x.test", "b@x.test"}, 5); got != "a@x.test, b@x.test" {
		t.Errorf("firstFew(2 items) = %q", got)
	}

	items := []string{"a@x.test", "b@x.test", "c@x.test", "d@x.test"}
	got := firstFew(items, 2)
	if !strings.Contains(got, "(+2 more)") || strings.Count(got, "@x.test") != 2 {
		t.Errorf("firstFew(4 items, 2) = %q, want two addresses and a count of the rest", got)
	}
}
