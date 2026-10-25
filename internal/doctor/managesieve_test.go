package doctor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/config"
)

// TestProtocolsIncludeSieve pins the parse that decides whether managesieved
// starts at all.
func TestProtocolsIncludeSieve(t *testing.T) {
	cases := []struct {
		name string
		conf string
		want bool
	}{
		{"the installer's line before this fix", "protocols = imap pop3 lmtp\n", false},
		{"after the fix", "protocols = imap pop3 lmtp sieve\n", true},
		{"no spaces around the assignment", "protocols=imap pop3 lmtp sieve\n", true},
		{"commented out", "# protocols = imap pop3 lmtp sieve\n", false},
		{"trailing comment", "protocols = imap sieve # filters\n", true},
		{"last assignment wins", "protocols = imap sieve\nprotocols = imap pop3\n", false},
		{"a sieve_* protocol is not sieve", "protocols = sieve_deprecated\n", false},
		{"protocol blocks are not the setting", "protocol imap {\n  mail_plugins = sieve\n}\n", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		if got := protocolsIncludeSieve(c.conf); got != c.want {
			t.Errorf("%s: protocolsIncludeSieve(%q) = %v, want %v", c.name, c.conf, got, c.want)
		}
	}
}

// TestManagesieveCheckReportsTheMissingProtocol is the check that would have
// turned "the Filters page cannot connect" into one line with a fix in it.
func TestManagesieveCheckReportsTheMissingProtocol(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dovecot.conf"),
		[]byte("protocols = imap pop3 lmtp\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := managesieveCheck(Options{Config: &config.Config{
		Mail: config.MailConfig{DovecotConfDir: dir},
	}})

	if got.Name != "managesieved (filters)" {
		t.Fatalf("name = %q", got.Name)
	}
	if got.Status != Warn {
		t.Errorf("status = %q, want %q", got.Status, Warn)
	}
	if got.Hint == "" {
		t.Error("no hint: the operator is told something is wrong without being told what to do")
	}
}

// TestManagesieveCheckReportsTheMissingListener covers the second, independent
// defect: `sieve` enabled, but no managesieve-login block to bind port 4190.
func TestManagesieveCheckReportsTheMissingListener(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dovecot.conf"),
		[]byte("protocols = imap pop3 lmtp sieve\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "conf.d", "10-master.conf"),
		[]byte("service imap-login {\n  inet_listener imap {\n    port = 143\n  }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := managesieveCheck(Options{Config: &config.Config{
		Mail: config.MailConfig{DovecotConfDir: dir},
	}})
	if got.Status != Warn {
		t.Fatalf("status = %q, want %q (%s)", got.Status, Warn, got.Detail)
	}
}

// TestManagesieveCheckIsQuietOffTheMailServer keeps the check out of the way on
// a developer's machine, where there is no Dovecot at all.
func TestManagesieveCheckIsQuietOffTheMailServer(t *testing.T) {
	if got := managesieveCheck(Options{}); got.Name != "" {
		t.Errorf("managesieveCheck with no config = %+v, want no check", got)
	}

	got := managesieveCheck(Options{Config: &config.Config{
		Mail: config.MailConfig{DovecotConfDir: t.TempDir()},
	}})
	if got.Status != Info {
		t.Errorf("status = %q, want %q", got.Status, Info)
	}
}
