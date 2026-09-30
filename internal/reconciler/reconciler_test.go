package reconciler

import (
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/models"
)

func fixtureSnapshot() *models.Snapshot {
	return &models.Snapshot{
		Domains: []models.Domain{
			{
				ID: 1, Name: "example.com", IsPrimary: true, Active: true,
				DKIMSelector:       "default",
				DKIMPrivateKeyPath: "/etc/opendkim/keys/example.com/default.private",
			},
			{
				ID: 2, Name: "example.org", Active: true,
				DKIMSelector:       "default",
				DKIMPrivateKeyPath: "/etc/opendkim/keys/example.org/default.private",
			},
		},
		Users: []models.User{
			{ID: 1, DomainID: 1, Username: "alice", Email: "alice@example.com",
				PasswordHash: "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=4$AAA$BBB",
				QuotaMB:      2048, Active: true, DomainName: "example.com"},
			{ID: 2, DomainID: 1, Username: "bob", Email: "bob@example.com",
				PasswordHash: "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=4$CCC$DDD",
				QuotaMB:      1024, Active: true, DomainName: "example.com"},
			{ID: 3, DomainID: 2, Username: "carol", Email: "carol@example.org",
				PasswordHash: "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=4$EEE$FFF",
				QuotaMB:      1024, Active: true, DomainName: "example.org"},
		},
		Aliases: []models.Alias{
			{ID: 1, DomainID: 1, Source: "sales", Destination: "alice@example.com,bob@example.com"},
			{ID: 2, DomainID: 1, Source: "postmaster", Destination: "alice@example.com"},
		},
	}
}

func TestRenderVirtualMap(t *testing.T) {
	snap := fixtureSnapshot()
	out := string(RenderVirtualMap(snap))

	// Must contain self-maps for all users
	for _, want := range []string{
		"alice@example.com\talice@example.com",
		"bob@example.com\tbob@example.com",
		"carol@example.org\tcarol@example.org",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing user line: %q", want)
		}
	}

	// Must contain aliases
	if !strings.Contains(out, "sales@example.com\talice@example.com,bob@example.com") {
		t.Errorf("missing sales alias")
	}
	if !strings.Contains(out, "postmaster@example.com\talice@example.com") {
		t.Errorf("missing postmaster alias")
	}

	// Deterministic ordering
	out2 := string(RenderVirtualMap(snap))
	if out != out2 {
		t.Errorf("output not deterministic")
	}
}

func TestRenderVmailboxMap(t *testing.T) {
	snap := fixtureSnapshot()
	out := string(RenderVmailboxMap(snap))

	if !strings.Contains(out, "alice@example.com\t/var/mail/vhosts/example.com/alice/Maildir/") {
		t.Errorf("missing alice vmailbox path; got:\n%s", out)
	}
	if !strings.Contains(out, "carol@example.org\t/var/mail/vhosts/example.org/carol/Maildir/") {
		t.Errorf("missing carol vmailbox path")
	}
}

func TestRenderDovecotPasswd(t *testing.T) {
	snap := fixtureSnapshot()
	out := string(RenderDovecotPasswd(snap))

	// Format: email:hash:uid:gid:gecos:home:shell:extra
	for _, want := range []string{
		"alice@example.com:{ARGON2ID}",
		":5000:5000::/var/mail/vhosts/example.com/alice::userdb_quota_rule=*:storage=2048M",
		"bob@example.com:",
		":storage=1024M",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing fragment %q in output:\n%s", want, out)
		}
	}
}

func TestRenderPostfixMainCF(t *testing.T) {
	snap := fixtureSnapshot()
	out := string(RenderPostfixMainCF(snap, "mail.example.com"))

	for _, want := range []string{
		"myhostname = mail.example.com",
		"mydomain = example.com",
		"virtual_mailbox_domains = example.com, example.org",
		"virtual_mailbox_base = /var/mail/vhosts",
		// Ownership is per recipient now, not `static:5000`: a mailbox on a
		// real Unix account has to be delivered as that account.
		"virtual_uid_maps = hash:/etc/postfix/vuidmaps",
		"virtual_gid_maps = hash:/etc/postfix/vgidmaps",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestRenderKeyTable(t *testing.T) {
	snap := fixtureSnapshot()
	out := string(RenderKeyTable(snap, "/etc/opendkim"))

	want := "default._domainkey.example.com example.com:default:/etc/opendkim/keys/example.com/default.private"
	if !strings.Contains(out, want) {
		t.Errorf("missing keytable line %q", want)
	}
}

func TestIdempotentRendering(t *testing.T) {
	// Rendering the same snapshot twice must produce identical bytes.
	snap := fixtureSnapshot()

	renderers := map[string]func() []byte{
		"virtual":     func() []byte { return RenderVirtualMap(snap) },
		"vmailbox":    func() []byte { return RenderVmailboxMap(snap) },
		"vuidmaps":    func() []byte { return RenderVirtualUidMaps(snap) },
		"vgidmaps":    func() []byte { return RenderVirtualGidMaps(snap) },
		"helo_access": func() []byte { return RenderHeloAccess(snap, "mail.example.com") },
		"keytable":    func() []byte { return RenderKeyTable(snap, "/etc/opendkim") },
		"signing":     func() []byte { return RenderSigningTable(snap) },
		"trusted":     func() []byte { return RenderTrustedHosts(snap, "mail.example.com") },
		"passwd":      func() []byte { return RenderDovecotPasswd(snap) },
	}

	for name, fn := range renderers {
		a, b := fn(), fn()
		if string(a) != string(b) {
			t.Errorf("%s: non-deterministic output", name)
		}
	}
}
