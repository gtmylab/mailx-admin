package reconciler

import (
	"reflect"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

func TestPlanDKIMKeyOwnership(t *testing.T) {
	snap := fixtureSnapshot()

	got := planDKIMKeyOwnership(snap)

	want := []dkimKeySpec{
		{path: "/etc/opendkim/keys", mode: 0o750},
		{path: "/etc/opendkim/keys/example.com", mode: 0o750},
		{path: "/etc/opendkim/keys/example.com/default.private", mode: 0o600, file: true},
		{path: "/etc/opendkim/keys/example.org", mode: 0o750},
		{path: "/etc/opendkim/keys/example.org/default.private", mode: 0o600, file: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestPlanDKIMKeyOwnershipSkipsDomainsWithoutKeys(t *testing.T) {
	snap := fixtureSnapshot()
	snap.Domains = []models.Domain{{ID: 9, Name: "nokey.example", Active: true}}

	if got := planDKIMKeyOwnership(snap); len(got) != 0 {
		t.Fatalf("planned ownership for a domain with no key: %#v", got)
	}
}
