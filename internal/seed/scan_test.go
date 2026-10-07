package seed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// systemFixture lays out what "Add MailX User" — or a plain `useradd -m` — leaves
// on a server: /etc/passwd entries, /etc/shadow hashes, a maildir per account and
// the installer's .dovecot.quota note.
//
// The home directories live inside a temp dir, so the scanner sees absolute paths
// exactly as it would on a real server, without the test needing /home.
type systemFixture struct {
	passwd string
	shadow string
	home   string // the mailbox account's home, as /etc/passwd spells it
}

// passwdPath renders a real directory as a path /etc/passwd can hold.
//
// The file is colon-separated, so a Windows drive prefix ("C:\...") cannot appear
// in it — a real passwd file never has one. Dropping the drive keeps the path
// absolute and points at the same directory, which is what lets these tests run
// on a workstation instead of skipping there.
func passwdPath(abs string) string {
	if _, rest, ok := strings.Cut(abs, ":"); ok {
		return `\` + strings.TrimPrefix(rest, `\`)
	}
	return abs
}

func newSystemFixture(t *testing.T) systemFixture {
	t.Helper()
	dir := t.TempDir()

	// A real mailbox: account, maildir, and the quota note the installer writes.
	homeDir := filepath.Join(dir, "home", "test1")
	if err := os.MkdirAll(filepath.Join(homeDir, "Maildir", "cur"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(homeDir, ".dovecot.quota"), "quota_rule = *:storage=2048M\n")
	home := passwdPath(homeDir)

	// A shell account with no maildir: it is an account, not a mailbox.
	shellHome := passwdPath(mkdirTemp(t, dir, "home", "shellonly"))

	// A service account that does have a maildir: only its uid excludes it.
	serviceHome := passwdPath(mkdirTemp(t, dir, "var", "deploy"))
	mkdirTemp(t, dir, "var", "deploy", "Maildir")

	// A real mailbox whose password is locked: importing it would create an
	// account nobody can log into.
	lockedHome := passwdPath(mkdirTemp(t, dir, "home", "locked"))
	mkdirTemp(t, dir, "home", "locked", "Maildir")

	passwd := filepath.Join(dir, "passwd")
	writeTestFile(t, passwd, strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
		"vmail:x:5000:5000::/var/mail/vmail:/usr/sbin/nologin",
		"deploy:x:999:999::" + serviceHome + ":/bin/bash",
		"test1:x:1000:1000::" + home + ":/bin/bash",
		"shellonly:x:1001:1001::" + shellHome + ":/bin/bash",
		"locked:x:1002:1002::" + lockedHome + ":/bin/bash",
	}, "\n")+"\n")

	shadow := filepath.Join(dir, "shadow")
	writeTestFile(t, shadow, strings.Join([]string{
		"root:*:19000:0:99999:7:::",
		"vmail:!:19000:0:99999:7:::",
		"deploy:$6$rounds=5000$abcdefgh$deployhash:19000:0:99999:7:::",
		"test1:$6$rounds=5000$abcdefgh$test1hash:19000:0:99999:7:::",
		"shellonly:$6$rounds=5000$abcdefgh$shellhash:19000:0:99999:7:::",
		"locked:!:19000:0:99999:7:::",
	}, "\n")+"\n")

	return systemFixture{
		passwd: passwd,
		shadow: shadow,
		home:   home,
	}
}

// mkdirTemp creates a directory tree under the fixture and returns its path.
func mkdirTemp(t *testing.T, dir string, elems ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{dir}, elems...)...)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f systemFixture) options() Options {
	return Options{PasswdFile: f.passwd, ShadowFile: f.shadow}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestScanSystemMailboxesFindsTheUseraddMailbox is the bug: the mailbox exists on
// the server, the panel has never heard of it, and nothing but the server's own
// files can tell the panel it is there.
func TestScanSystemMailboxesFindsTheUseraddMailbox(t *testing.T) {
	fx := newSystemFixture(t)

	found := scanSystemMailboxes(fx.options(), "example.com", map[string]bool{})

	if len(found) != 1 {
		t.Fatalf("found %d mailboxes, want exactly the one real user account: %+v", len(found), found)
	}
	u := found[0]
	if u.Email != "test1@example.com" || u.LocalPart != "test1" || u.Domain != "example.com" {
		t.Errorf("address = %s (local %q, domain %q), want test1@example.com", u.Email, u.LocalPart, u.Domain)
	}
	if u.Kind != "system" {
		t.Errorf("kind = %q, want system so the renderer keeps the account's own uid/gid/home", u.Kind)
	}
	if u.SysUID != 1000 || u.SysGID != 1000 || u.Home != fx.home {
		t.Errorf("account = uid %d gid %d home %s, want 1000/1000 %s", u.SysUID, u.SysGID, u.Home, fx.home)
	}
	// {CRYPT} and not argon2id: the account's own password is being reused, so
	// that `passwd`, SSH and the panel keep agreeing.
	if u.PasswordHash != "{CRYPT}$6$rounds=5000$abcdefgh$test1hash" {
		t.Errorf("hash = %q, want the account's crypt hash with the {CRYPT} scheme", u.PasswordHash)
	}
	// The quota comes from the note the installer left behind; without this the
	// mailbox silently reverts to the default.
	if u.QuotaMB != 2048 {
		t.Errorf("quota = %d MB, want 2048 from .dovecot.quota", u.QuotaMB)
	}
}

// TestScanSystemMailboxesExcludesWhatIsNotAMailbox walks the ways an account can
// fail to be one. Each case is the difference between a panel that lists real
// mailboxes and one that invents addresses.
func TestScanSystemMailboxesExcludesWhatIsNotAMailbox(t *testing.T) {
	t.Run("locked password", func(t *testing.T) {
		fx := newSystemFixture(t)
		writeTestFile(t, fx.shadow, "test1:!:19000:0:99999:7:::\n")
		if found := scanSystemMailboxes(fx.options(), "example.com", nil); len(found) != 0 {
			t.Errorf("found %+v, want nothing: a locked password imports an account nobody can log into", found)
		}
	})

	t.Run("no password at all", func(t *testing.T) {
		fx := newSystemFixture(t)
		writeTestFile(t, fx.shadow, "test1:*:19000:0:99999:7:::\n") // "*" means no password
		if found := scanSystemMailboxes(fx.options(), "example.com", nil); len(found) != 0 {
			t.Errorf("found %+v, want nothing", found)
		}
	})

	t.Run("unreadable shadow database", func(t *testing.T) {
		fx := newSystemFixture(t)
		// No shadow file at all: the panel cannot know the password, and
		// guessing would be worse than reporting the mailbox as skipped.
		opts := fx.options()
		opts.ShadowFile = filepath.Join(t.TempDir(), "missing-shadow")
		if found := scanSystemMailboxes(opts, "example.com", nil); len(found) != 0 {
			t.Errorf("found %+v, want nothing without a password database", found)
		}
	})

	t.Run("no maildir", func(t *testing.T) {
		fx := newSystemFixture(t)
		// Same account, maildir removed: a shell account, not a mailbox.
		if err := os.RemoveAll(filepath.Join(fx.home, "Maildir")); err != nil {
			t.Fatal(err)
		}
		if found := scanSystemMailboxes(fx.options(), "example.com", nil); len(found) != 0 {
			t.Errorf("found %+v, want nothing without a maildir", found)
		}
	})

	t.Run("no login shell", func(t *testing.T) {
		fx := newSystemFixture(t)
		writeTestFile(t, fx.passwd, "test1:x:1000:1000::"+fx.home+":/usr/sbin/nologin\n")
		if found := scanSystemMailboxes(fx.options(), "example.com", nil); len(found) != 0 {
			t.Errorf("found %+v, want nothing for a service account", found)
		}
	})

	t.Run("uid below the first user account", func(t *testing.T) {
		fx := newSystemFixture(t)
		writeTestFile(t, fx.passwd, "test1:x:999:999::"+fx.home+":/bin/bash\n")
		if found := scanSystemMailboxes(fx.options(), "example.com", nil); len(found) != 0 {
			t.Errorf("found %+v, want nothing for uid 999", found)
		}
	})

	t.Run("already in the passwd-file", func(t *testing.T) {
		fx := newSystemFixture(t)
		// The panel already manages it; importing it twice would put two
		// entries with one address into the plan.
		found := scanSystemMailboxes(fx.options(), "example.com",
			map[string]bool{"test1@example.com": true})
		if len(found) != 0 {
			t.Errorf("found %+v, want nothing for a mailbox the panel already has", found)
		}
	})

	t.Run("no domain to attribute it to", func(t *testing.T) {
		fx := newSystemFixture(t)
		if found := scanSystemMailboxes(fx.options(), "", nil); found != nil {
			t.Errorf("found %+v, want nothing without a domain", found)
		}
	})

	t.Run("explicit domain override", func(t *testing.T) {
		fx := newSystemFixture(t)
		opts := fx.options()
		opts.SystemMailDomain = "override.test"
		found := scanSystemMailboxes(opts, "example.com", nil)
		if len(found) != 1 || found[0].Email != "test1@override.test" {
			t.Errorf("found %+v, want the mailbox on the override domain", found)
		}
	})
}
func TestParseQuotaRule(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"userdb_quota_rule=*:storage=2048M", 2048}, // the panel's passwd-file
		{"quota_rule = *:storage=2048M\n", 2048},    // the installer's note
		{"storage=1G", 1024},                        // gigabytes
		{"storage=2T", 2 * 1024 * 1024},             // terabytes
		{"storage=1048576B", 1},                     // bytes, rounded up
		{"storage=2048", 1},                         // a bare number is bytes
		{"storage=10X", 0},                          // unknown suffix: not a size we understand
		{"no quota rule here", 0},
		{"storage=", 0},
	}
	for _, c := range cases {
		if got := parseQuotaRule(c.in); got != c.want {
			t.Errorf("parseQuotaRule(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseQuotaFromHome(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, ".dovecot.quota"), "quota_rule = *:storage=5120M\n")

	if got := parseQuotaFromHome(dir); got != 5120 {
		t.Errorf("parseQuotaFromHome = %d, want 5120", got)
	}
	if got := parseQuotaFromHome(filepath.Join(dir, "nope")); got != 0 {
		t.Errorf("parseQuotaFromHome on a missing home = %d, want 0", got)
	}
	if got := parseQuotaFromHome(""); got != 0 {
		t.Errorf("parseQuotaFromHome(\"\") = %d, want 0", got)
	}
}

// TestLookupSystemAccount is what `mailbox add --kind system` uses to adopt an

func TestScanAliases(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "virtual"), strings.Join([]string{
		"sales@example.com     alice@example.com,bob@example.com",
		"postmaster@example.com alice@example.com",
		"@example.com          catchall@example.com",
		"alice@example.com     alice@example.com", // self-map: skipped
		"# a comment line",
	}, "\n")+"\n")

	aliases := scanAliases(dir)
	if len(aliases) != 3 {
		t.Fatalf("scanAliases = %d aliases, want 3: %+v", len(aliases), aliases)
	}

	got := map[string]string{}
	for _, a := range aliases {
		got[a.Source] = a.Domain + " -> " + a.Destination
	}

	if got["sales"] != "example.com -> alice@example.com,bob@example.com" {
		t.Errorf("forwarder sales wrong: %+v", aliases)
	}
	if got["postmaster"] != "example.com -> alice@example.com" {
		t.Errorf("forwarder postmaster wrong: %+v", aliases)
	}
	// The catch-all must be canonicalized to "@example.com", not stored as "".
	if got["@example.com"] != "example.com -> catchall@example.com" {
		t.Errorf("catch-all not canonicalized to @domain: %+v", aliases)
	}
}

// account instead of inventing a second one with the same name.
func TestLookupSystemAccount(t *testing.T) {
	fx := newSystemFixture(t)

	acct, err := LookupSystemAccount(fx.options(), "test1")
	if err != nil {
		t.Fatalf("LookupSystemAccount: %v", err)
	}
	if acct == nil {
		t.Fatal("account not found")
	}
	if acct.UID != 1000 || acct.GID != 1000 || acct.Home != fx.home {
		t.Errorf("account = uid %d gid %d home %s, want 1000/1000 %s",
			acct.UID, acct.GID, acct.Home, fx.home)
	}
	if acct.PasswordHash != "{CRYPT}$6$rounds=5000$abcdefgh$test1hash" {
		t.Errorf("hash = %q, want the account's crypt hash with the {CRYPT} scheme", acct.PasswordHash)
	}

	// Absent is an answer here, not an error.
	missing, err := LookupSystemAccount(fx.options(), "nosuchuser")
	if err != nil || missing != nil {
		t.Errorf("LookupSystemAccount(nosuchuser) = %+v, %v; want nil, nil", missing, err)
	}

	// A locked account is found, but has no password to adopt.
	if acct, err := LookupSystemAccount(fx.options(), "locked"); err != nil {
		t.Errorf("LookupSystemAccount(locked): %v", err)
	} else if acct == nil || acct.PasswordHash != "" {
		t.Errorf("locked = %+v, want the account with no usable hash", acct)
	}
}
