package roundcube

import (
	"context"
	"strings"
	"testing"
	"time"
)

func testClient() *Client {
	return New(Config{Database: "roundcubemail", MailHost: "localhost", Language: "en_GB"})
}

// TestEnsureUserSQL: the script is the whole feature, so what it says matters.
func TestEnsureUserSQL(t *testing.T) {
	c := testClient()
	sql, err := c.ensureUserSQL("alice@example.com")
	if err != nil {
		t.Fatalf("ensureUserSQL: %v", err)
	}

	// Both rows, and the identity tied to the user row this call owns.
	for _, want := range []string{
		"users (username, mail_host, created, last_login, language, preferences)",
		"identities (user_id, changed, del, standard, name, organization, email, signature, html_signature)",
		"SET @uid = IF(@existed = 0, LAST_INSERT_ID()",
		"SELECT @existed, @uid, @hasidentity;",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("the script is missing %q:\n%s", want, sql)
		}
	}

	// Roundcube's unique key is (mail_host, username) and its own lookups use
	// both, so the two existence checks on `users` have to as well — otherwise
	// a mailbox of the same name on another host is treated as one of ours.
	if n := strings.Count(sql, "FROM users WHERE username = 'alice@example.com' AND mail_host = 'localhost'"); n != 2 {
		t.Errorf("%d lookups filter on mail_host, want 2:\n%s", n, sql)
	}

	// The identity name defaults to the local part, which is what the
	// installer writes too.
	if !strings.Contains(sql, "'alice', 'localhost', 'alice@example.com'") {
		t.Errorf("the identity does not use the local part as its name:\n%s", sql)
	}

	// Preferences are the installer's blob, byte for byte, so a mailbox
	// created here and one created there start the same way. Its own double
	// quotes are escaped for the literal.
	escaped := strings.ReplaceAll(DefaultPreferences, `"`, `\"`)
	if !strings.Contains(sql, escaped) {
		t.Errorf("the preference blob is missing:\n%s", sql)
	}

	// The target table is never read from inside its own insert (MySQL error
	// 1093); the session variables are what make that unnecessary.
	if strings.Contains(sql, "NOT EXISTS (SELECT 1 FROM users") {
		t.Error("the users insert reads the table it writes, which MySQL rejects")
	}
}

// TestEnsureUserSQLEscapesValues: the one place an email address reaches SQL.
func TestEnsureUserSQLEscapesValues(t *testing.T) {
	c := testClient()
	sql, err := c.ensureUserSQL(`o'brien@example.com`)
	if err != nil {
		t.Fatalf("ensureUserSQL: %v", err)
	}
	if !strings.Contains(sql, `'o\'brien@example.com'`) {
		t.Errorf("the apostrophe was not escaped:\n%s", sql)
	}
}

// TestEnsureUserSQLRejectsBadDatabaseName: the database name is the only
// identifier spliced in unquoted.
func TestEnsureUserSQLRejectsBadDatabaseName(t *testing.T) {
	c := New(Config{Database: "roundcubemail; DROP DATABASE mailx"})
	if _, err := c.ensureUserSQL("alice@example.com"); err == nil {
		t.Fatal("a database name with a semicolon was accepted")
	}
}

func TestValidateLogin(t *testing.T) {
	cases := map[string]bool{
		"alice@example.com":    true,
		"a.b+c@sub.example.io": true,
		"":                     false,
		"alice":                false,
		"alice@example@org":    false,
		"alice smith@example":  false,
		"alice\n@example.com":  false,
	}

	for login, ok := range cases {
		err := validateLogin(login)
		if ok && err != nil {
			t.Errorf("validateLogin(%q) = %v, want nil", login, err)
		}
		if !ok && err == nil {
			t.Errorf("validateLogin(%q) = nil, want an error", login)
		}
	}
}

// TestParseEnsureOutput: execx merges stderr into the output, so the answer has
// to be read from the end. A MySQL client that warns about a password on the
// command line is the normal case, not an exotic one.
func TestParseEnsureOutput(t *testing.T) {
	existed, uid, hadIdentity, err := parseEnsureOutput("0\t42\t0\n")
	if err != nil {
		t.Fatalf("parseEnsureOutput(new user): %v", err)
	}
	if existed || uid != 42 || hadIdentity {
		t.Errorf("= %v, %d, %v; want false, 42, false", existed, uid, hadIdentity)
	}

	existed, uid, hadIdentity, err = parseEnsureOutput(
		"mysql: [Warning] Using a password on the command line interface can be insecure.\n1\t7\t1\n")
	if err != nil {
		t.Fatalf("parseEnsureOutput(known user, with a warning): %v", err)
	}
	if !existed || uid != 7 || !hadIdentity {
		t.Errorf("= %v, %d, %v; want true, 7, true", existed, uid, hadIdentity)
	}

	for _, bad := range []string{"", "nothing here", "1\t2", "0\t0\t1", "x\ty\tz"} {
		if _, _, _, err := parseEnsureOutput(bad); err == nil {
			t.Errorf("parseEnsureOutput(%q) returned no error", bad)
		}
	}
}

// TestNormalizeDefaults: a Config built by hand behaves like one loaded from
// admin.toml, so the doctor and the CLI agree on what "not configured" means.
func TestNormalizeDefaults(t *testing.T) {
	cfg := Config{}.Normalize()

	if cfg.Database != DefaultDatabase || cfg.Binary != DefaultBinary ||
		cfg.MailHost != DefaultMailHost || cfg.Language != DefaultLanguage ||
		cfg.Timeout != DefaultTimeout || cfg.Preferences != DefaultPreferences {
		t.Errorf("Normalize() = %+v, want every default filled in", cfg)
	}

	// mail_host has to stay in step with Roundcube's imap_host/default_host,
	// which is why it is configurable at all.
	custom := Config{MailHost: "mail.example.com", Timeout: 5 * time.Second}.Normalize()
	if custom.MailHost != "mail.example.com" || custom.Timeout != 5*time.Second {
		t.Errorf("Normalize() overrode an explicit value: %+v", custom)
	}
}

// TestEnsureUserWithoutTheClient: a host with no MySQL client must get a
// sentence that says so, not an exec error. This is the one path that can be
// exercised without a database.
func TestEnsureUserWithoutTheClient(t *testing.T) {
	c := New(Config{Binary: "mailx-there-is-no-such-client"})

	_, err := c.EnsureUser(context.Background(), "alice@example.com")
	if err == nil {
		t.Fatal("EnsureUser with a missing client returned no error")
	}
	if !strings.Contains(err.Error(), "not installed") {
		t.Errorf("err = %v, want it to say the client is not installed", err)
	}
}
