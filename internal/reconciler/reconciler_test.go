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
			{ID: 3, DomainID: 1, Source: "@example.com", Destination: "alice@example.com"},
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
	if !strings.Contains(out, "@example.com\talice@example.com") {
		t.Errorf("missing catch-all alias; got:\n%s", out)
	}

	// Deterministic ordering
	out2 := string(RenderVirtualMap(snap))
	if out != out2 {
		t.Errorf("output not deterministic")
	}
}

func TestRenderVirtualMapCatchAllLegacyForms(t *testing.T) {
	// Rows written before catch-all was canonicalized to "@domain" may carry a
	// bare "@" (from the UI) or an empty source (from the seed). Both must
	// render as the domain's catch-all, never as a bare "@".
	for _, source := range []string{"@", ""} {
		snap := fixtureSnapshot()
		snap.Aliases = []models.Alias{
			{ID: 1, DomainID: 1, Source: source, Destination: "alice@example.com"},
		}
		out := string(RenderVirtualMap(snap))
		if !strings.Contains(out, "@example.com\talice@example.com") {
			t.Errorf("catch-all source %q did not render as @example.com; got:\n%s", source, out)
		}
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
		// The mail domain must not be local, or virtual mailboxes bounce.
		"mydestination = localhost, localhost.$mydomain",
		"virtual_mailbox_domains = example.com, example.org",
		// Overrides the installer's alias-domain table, which would otherwise
		// classify every domain as alias-only (no mailbox delivery).
		"virtual_alias_domains =",
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

	// A mail domain in mydestination is the bug that bounced every virtual
	// mailbox: it made Postfix deliver locally, where no Unix account exists.
	for _, notWant := range []string{
		"mydestination = $myhostname",
		", $mydomain",
	} {
		if strings.Contains(out, notWant) {
			t.Errorf("mydestination still names a mail domain (found %q):\n%s", notWant, out)
		}
	}
}

// TestMergeMainCF — the managed block has to land in the main.cf Postfix reads,
// replacing any previous block rather than growing the file on every reconcile.
func TestMergeMainCF(t *testing.T) {
	managed := RenderPostfixMainCF(fixtureSnapshot(), "mail.example.com")

	// Fresh main.cf (no managed block yet): the block is appended.
	template := []byte("smtpd_banner = $myhostname ESMTP\n")
	merged := string(mergeMainCF(template, managed))
	if !strings.Contains(merged, "smtpd_banner = $myhostname ESMTP") {
		t.Errorf("merge dropped the template:\n%s", merged)
	}
	if !strings.Contains(merged, "# BEGIN mailx-admin managed block") {
		t.Errorf("merge did not append the managed block:\n%s", merged)
	}

	// Re-running is idempotent: the old block is replaced, not duplicated.
	twice := mergeMainCF([]byte(merged), managed)
	if got := strings.Count(string(twice), "# BEGIN mailx-admin managed block"); got != 1 {
		t.Errorf("merged main.cf has %d managed blocks, want 1:\n%s", got, twice)
	}
	if got := strings.Count(string(twice), "virtual_mailbox_domains ="); got != 1 {
		t.Errorf("merged main.cf has %d virtual_mailbox_domains lines, want 1:\n%s", got, twice)
	}
	if got := strings.Count(string(twice), "smtpd_banner = $myhostname ESMTP"); got != 1 {
		t.Errorf("merged main.cf has %d smtpd_banner lines, want 1:\n%s", got, twice)
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

func TestRenderOpenDKIMConf(t *testing.T) {
	out := string(RenderOpenDKIMConf("/etc/opendkim"))

	for _, want := range []string{
		"KeyTable",
		"SigningTable",
		"refile:",
		"InternalHosts",
		"ExternalIgnoreList",
		"/etc/opendkim/KeyTable",
		"/etc/opendkim/SigningTable",
		"file:/etc/opendkim/TrustedHosts",
		"local:/var/spool/postfix/opendkim/opendkim.sock",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	// Single-domain directives would lock OpenDKIM to one domain and ignore the
	// tables; the managed conf must not carry any of them.
	for _, notWant := range []string{"KeyFile", "Selector "} {
		if strings.Contains(out, notWant) {
			t.Errorf("single-domain directive %q still present in:\n%s", notWant, out)
		}
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
