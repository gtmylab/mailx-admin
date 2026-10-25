package reconciler

import (
	"reflect"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// TestPlanSieveOwnership pins who has to own a managed Sieve script.
//
// The bug this guards against is silent in both directions: a script written
// 0600 root:root is never executed (delivery cannot read it) and ManageSieve
// cannot save over it, and a system mailbox's script planned under
// /var/mail/vhosts is a file Dovecot never looks at. Neither produces an error
// anywhere -- the filters simply do nothing.
func TestPlanSieveOwnership(t *testing.T) {
	snap := &models.Snapshot{
		Domains: []models.Domain{{ID: 1, Name: "example.com", Active: true}},
		Users: []models.User{
			{ID: 1, DomainID: 1, Username: "alice", Email: "alice@example.com",
				Active: true, DomainName: "example.com"},
			// No rules: the renderer emits no script for this one, so there
			// is nothing to own.
			{ID: 2, DomainID: 1, Username: "bob", Email: "bob@example.com",
				Active: true, DomainName: "example.com"},
			// A real Unix account: its mail lives in its own home, not under
			// Postfix's virtual_mailbox_base.
			{ID: 3, DomainID: 1, Username: "svc", Email: "svc@example.com",
				Active: true, DomainName: "example.com",
				Kind: models.KindSystem, SysUID: 1001, SysGID: 1002, Home: "/home/svc"},
		},
		SieveRules: map[int64][]models.SieveRule{
			1: {{ID: 10, UserID: 1, RuleType: "vacation", Enabled: true}},
			3: {{ID: 11, UserID: 3, RuleType: "forward", Enabled: true}},
		},
	}

	got := planSieveOwnership(snap)
	want := []sieveScriptSpec{
		{
			path: "/var/mail/vhosts/example.com/alice/sieve/managesieve.sieve",
			uid:  models.VmailUID, gid: models.VmailGID,
		},
		{
			path: "/home/svc/sieve/managesieve.sieve",
			uid:  1001, gid: 1002,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

// TestSieveOwnerNeverReturnsNil matters because WriteFileOwned treats a nil
// owner as "do not touch ownership" -- the exact behaviour that produced the
// 0600 root:root scripts in the first place.
func TestSieveOwnerNeverReturnsNil(t *testing.T) {
	for _, u := range []models.User{
		{Username: "alice", DomainName: "example.com"},
		{Username: "svc", Kind: models.KindSystem, SysUID: 1001, SysGID: 1002, Home: "/home/svc"},
	} {
		if sieveOwner(u) == nil {
			t.Fatalf("sieveOwner(%q) = nil", u.Username)
		}
	}
}
