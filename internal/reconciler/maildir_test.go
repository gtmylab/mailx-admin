package reconciler

import (
	"context"
	"path"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// mixedSnapshot is one virtual mailbox and one that lives on a real Unix
// account: the shape the panel had no way to express before migration 006, and
// the shape the installer creates for "Add MailX User" / Roundcube.
func mixedSnapshot() *models.Snapshot {
	return &models.Snapshot{
		Domains: []models.Domain{
			{ID: 1, Name: "example.com", IsPrimary: true, Active: true, DKIMSelector: "default"},
		},
		Users: []models.User{
			{
				ID: 1, DomainID: 1, Username: "alice", Email: "alice@example.com",
				PasswordHash: "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=4$AAA$BBB",
				QuotaMB:      1024, Active: true, DomainName: "example.com",
				Kind: models.KindVirtual,
			},
			{
				ID: 2, DomainID: 1, Username: "test1", Email: "test1@example.com",
				PasswordHash: "{CRYPT}$6$rounds=5000$abcdefgh$xyz",
				QuotaMB:      2048, Active: true, DomainName: "example.com",
				Kind: models.KindSystem, SysUID: 1000, SysGID: 1000, Home: "/home/test1",
			},
		},
	}
}

func TestRenderDovecotPasswdKeepsEachAccountOwnOwnership(t *testing.T) {
	out := string(RenderDovecotPasswd(mixedSnapshot()))

	// The virtual mailbox keeps uid/gid 5000 and the vmail layout...
	wantVirtual := "alice@example.com:{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=4$AAA$BBB:5000:5000::" +
		"/var/mail/vhosts/example.com/alice::userdb_quota_rule=*:storage=1024M"
	if !strings.Contains(out, wantVirtual) {
		t.Errorf("virtual mailbox line wrong:\n%s", out)
	}

	// ...and the system mailbox keeps its own account, its own home and the
	// {CRYPT} hash it was imported with. Rendering it as 5000:5000 is what made
	// such a mailbox log in and then fail every folder with EACCES.
	wantSystem := "test1@example.com:{CRYPT}$6$rounds=5000$abcdefgh$xyz:1000:1000::/home/test1::" +
		"userdb_quota_rule=*:storage=2048M"
	if !strings.Contains(out, wantSystem) {
		t.Errorf("system mailbox line wrong:\n%s", out)
	}
}

func TestRenderVmailboxMapPerKind(t *testing.T) {
	out := string(RenderVmailboxMap(mixedSnapshot()))

	if !strings.Contains(out, "alice@example.com\t/var/mail/vhosts/example.com/alice/Maildir/") {
		t.Errorf("virtual delivery path wrong:\n%s", out)
	}
	if !strings.Contains(out, "test1@example.com\t/home/test1/Maildir/") {
		t.Errorf("system delivery path wrong:\n%s", out)
	}
}

func TestRenderOwnerMapsPerKind(t *testing.T) {
	uids := string(RenderVirtualUidMaps(mixedSnapshot()))
	gids := string(RenderVirtualGidMaps(mixedSnapshot()))

	for name, out := range map[string]string{"vuidmaps": uids, "vgidmaps": gids} {
		if !strings.Contains(out, "alice@example.com\t5000") {
			t.Errorf("%s: vmail mailbox must stay on 5000:\n%s", name, out)
		}
		if !strings.Contains(out, "test1@example.com\t1000") {
			t.Errorf("%s: system mailbox must be delivered as its own account:\n%s", name, out)
		}
	}
}

func TestPlanMaildirsMaterialisesBothKinds(t *testing.T) {
	plan := planMaildirs(mixedSnapshot())

	specs := map[string]maildirSpec{}
	for _, s := range plan {
		if _, dup := specs[s.path]; dup {
			t.Fatalf("duplicate entry for %s (a directory must be created once)", s.path)
		}
		specs[s.path] = s
	}

	// A virtual mailbox needs the domain directory (vmail-owned, so Postfix can
	// create the user's maildir on first delivery), the mailbox itself and the
	// Maildir skeleton.
	virtual := []struct {
		path string
		mode uint32
		uid  int
	}{
		{"/var/mail/vhosts/example.com", 0o770, models.VmailUID},
		{"/var/mail/vhosts/example.com/alice", 0o700, models.VmailUID},
		{"/var/mail/vhosts/example.com/alice/Maildir", 0o700, models.VmailUID},
		{"/var/mail/vhosts/example.com/alice/Maildir/cur", 0o700, models.VmailUID},
		{"/var/mail/vhosts/example.com/alice/Maildir/new", 0o700, models.VmailUID},
		{"/var/mail/vhosts/example.com/alice/Maildir/tmp", 0o700, models.VmailUID},
		{"/var/mail/vhosts/example.com/alice/sieve", 0o700, models.VmailUID},
	}
	for _, want := range virtual {
		got, ok := specs[want.path]
		if !ok {
			t.Errorf("missing %s from the plan", want.path)
			continue
		}
		if uint32(got.mode) != want.mode || got.uid != want.uid || got.gid != want.uid {
			t.Errorf("%s: got mode %o uid %d gid %d, want mode %o uid %d",
				want.path, got.mode, got.uid, got.gid, want.mode, want.uid)
		}
	}

	// A system mailbox already has /home/<user> from useradd; only what lives
	// inside it is ours, and it must belong to the account.
	for _, path := range []string{
		"/home/test1",
		"/home/test1/Maildir",
		"/home/test1/Maildir/cur",
		"/home/test1/Maildir/new",
		"/home/test1/Maildir/tmp",
		"/home/test1/sieve",
	} {
		got, ok := specs[path]
		if !ok {
			t.Errorf("missing %s from the plan", path)
			continue
		}
		if got.uid != 1000 || got.gid != 1000 {
			t.Errorf("%s: owner %d:%d, want 1000:1000", path, got.uid, got.gid)
		}
		if got.owner != "test1" {
			t.Errorf("%s: owner label %q, want the account name", path, got.owner)
		}
	}
}

func TestPlanMaildirsCreatesParentsBeforeChildrenAndSkipsInactive(t *testing.T) {
	snap := mixedSnapshot()
	snap.Users = append(snap.Users, models.User{
		ID: 3, DomainID: 1, Username: "gone", Email: "gone@example.com",
		QuotaMB: 100, Active: false, DomainName: "example.com",
	})

	plan := planMaildirs(snap)

	index := map[string]int{}
	for i, s := range plan {
		index[s.path] = i
		if strings.Contains(s.path, "gone") {
			t.Errorf("inactive mailbox planned: %s", s.path)
		}
	}

	// A child created before its parent leaves the parent root-owned and the
	// mailbox undeliverable, so the ordering is part of the contract.
	for _, s := range plan {
		parent := path.Dir(s.path)
		if pi, ok := index[parent]; ok && pi > index[s.path] {
			t.Errorf("%s scheduled before its parent %s", s.path, parent)
		}
	}
}

func TestEnsureMaildirsAccountsForEveryDirectory(t *testing.T) {
	// Every planned directory is either created or reported. Silence is the
	// failure mode that matters: a warning shows up in the dashboard, a missing
	// message does not.
	snap := mixedSnapshot()
	plan := planMaildirs(snap)

	created, warnings := ensureMaildirs(context.Background(), snap)

	reported := map[string]bool{}
	for _, p := range created {
		reported[p] = true
	}
	for _, w := range warnings {
		for _, s := range plan {
			if strings.HasPrefix(w, "create "+s.path+":") ||
				strings.HasPrefix(w, "fix ownership of "+s.path+":") ||
				strings.HasPrefix(w, "stat "+s.path+":") {
				reported[s.path] = true
			}
		}
	}

	for _, s := range plan {
		if !reported[s.path] {
			t.Errorf("%s: neither created nor warned about", s.path)
		}
	}
}
