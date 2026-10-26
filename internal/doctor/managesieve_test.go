package doctor

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gtmylab/mailx-admin/internal/config"
)

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

// TestManagesieveListenerConfiguredFindsTheDropIn pins the fix for a check that
// only read 10-master.conf: the panel writes the listener into its own
// conf.d/20-managesieve.conf, and a listener there is as real as one appended to
// 10-master.conf.
func TestManagesieveListenerConfiguredFindsTheDropIn(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "conf.d", "10-master.conf"),
		[]byte("service imap-login {\n  inet_listener imap {\n    port = 143\n  }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if managesieveListenerConfigured(dir) {
		t.Fatal("reported a listener although no file declares managesieve-login")
	}

	if err := os.WriteFile(filepath.Join(dir, "conf.d", "20-managesieve.conf"),
		[]byte("service managesieve-login {\n  inet_listener sieve {\n    port = 4190\n  }\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !managesieveListenerConfigured(dir) {
		t.Error("did not see the managesieve-login block in conf.d/20-managesieve.conf")
	}
}

// TestPHPsettingsReadsOnlyActiveAssignments is the parse behind the Roundcube
// half of the check: a commented-out sample must not read as a setting, and a
// value inside a block comment must not either.
func TestPHPsettingsReadsOnlyActiveAssignments(t *testing.T) {
	src := `<?php
// $config['managesieve_host'] = 'example.org';
$config['managesieve_host'] = '127.0.0.1';
$config['managesieve_usetls'] = false;
/* $config['managesieve_port'] = 4191; */
$config['plugins'] = ['managesieve', 'archive'];
?>`

	settings := phpSettings(src)
	if got := settings["managesieve_host"]; got != "'127.0.0.1'" {
		t.Errorf("managesieve_host = %q, want the active value", got)
	}
	if _, ok := settings["managesieve_port"]; ok {
		t.Error("a value inside a /* */ comment was read as a setting")
	}

	active := nonCommentLines(src)
	if strings.Contains(active, "example.org") {
		t.Error("nonCommentLines kept a // comment")
	}
	if !strings.Contains(active, "'managesieve'") {
		t.Error("nonCommentLines dropped an active line")
	}
}

// TestRoundcubeFiltersProblemNamesTheBrokenHalf walks the failures that all
// look like "Unable to connect to managesieve server!" from the operator's side
// and makes sure each one is named.
func TestRoundcubeFiltersProblemNamesTheBrokenHalf(t *testing.T) {
	write := func(t *testing.T, conf string, withPluginDir bool) string {
		t.Helper()
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "config"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "config", "config.inc.php"), []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
		if withPluginDir {
			if err := os.MkdirAll(filepath.Join(root, "plugins", "managesieve"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}

	good := `<?php
$config['managesieve_host'] = '127.0.0.1';
$config['managesieve_port'] = 4190;
$config['managesieve_usetls'] = false;
$config['plugins'] = ['managesieve'];
?>`

	cases := []struct {
		name   string
		conf   string
		plugin bool
		want   string // substring of the problem; "" means no problem
		found  bool
	}{
		{name: "working", conf: good, plugin: true, want: "", found: true},
		{name: "host", conf: strings.Replace(good, "'127.0.0.1'", "'mail.example.org'", 1), plugin: true,
			want: "points the managesieve plugin at", found: true},
		{name: "port", conf: strings.Replace(good, "= 4190;", "= 2000;", 1), plugin: true,
			want: "managesieve_port", found: true},
		{name: "tls", conf: strings.Replace(good, "= false;", "= true;", 1), plugin: true,
			want: "STARTTLS", found: true},
		{name: "plugin disabled", conf: strings.Replace(good, "['managesieve']", "[]", 1), plugin: true,
			want: "not enabled", found: true},
		{name: "plugin code missing", conf: good, plugin: false,
			want: "no plugins/managesieve directory", found: true},
		{name: "no roundcube", conf: "", plugin: false, want: "", found: false},
	}

	for _, c := range cases {
		var root string
		if c.found {
			root = write(t, c.conf, c.plugin)
		} else {
			root = t.TempDir()
		}

		problem, found := roundcubeFiltersProblem(root)
		if found != c.found {
			t.Errorf("%s: found = %v, want %v", c.name, found, c.found)
			continue
		}
		if !strings.Contains(problem, c.want) {
			t.Errorf("%s: problem = %q, want it to contain %q", c.name, problem, c.want)
		}
	}
}

// TestManagesieveGreetingReadsTheGreeting covers the check that separates a
// closed port from a port that answers with something else, both of which
// Roundcube reports identically.
func TestManagesieveGreetingReadsTheGreeting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	logout := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"\r\n\"SIEVE\" \"envelope\"\r\nOK\r\n")

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		n, _ := conn.Read(buf)
		logout <- string(buf[:n])
	}()

	greeting, err := managesieveGreeting(ln.Addr().String())
	if err != nil {
		t.Fatalf("managesieveGreeting: %v", err)
	}
	if !strings.Contains(greeting, "IMPLEMENTATION") {
		t.Errorf("greeting = %q, want the ManageSieve greeting", greeting)
	}

	select {
	case got := <-logout:
		if !strings.HasPrefix(strings.ToUpper(got), "LOGOUT") {
			t.Errorf("client sent %q, want LOGOUT (an abandoned session is logged as an error)", got)
		}
	case <-time.After(3 * time.Second):
		t.Error("client never said LOGOUT")
	}
}

// TestManagesieveGreetingRejectsASilentListener pins that a socket which
// accepts and closes without saying anything is an error, not an empty success.
func TestManagesieveGreetingRejectsASilentListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	if greeting, err := managesieveGreeting(ln.Addr().String()); err == nil {
		t.Errorf("managesieveGreeting = %q, nil error, want an error for a silent port", greeting)
	}
}
