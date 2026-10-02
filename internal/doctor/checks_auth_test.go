package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtmylab/mailx-admin/internal/config"
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
			name:    "unprefixed hashes with the default Dovecot itself uses",
			counts:  map[string]int{"(default)": 1},
			schemes: dovecot.ParseSchemes("PLAIN, CRYPT, SHA512, SSHA512"),
			def:     dovecot.DefaultPassdbScheme,
		},
		{
			name:     "unprefixed hashes on a Dovecot with no crypt() either",
			counts:   map[string]int{"(default)": 1},
			schemes:  dovecot.ParseSchemes("PLAIN, SHA512"),
			def:      dovecot.DefaultPassdbScheme,
			wantSubs: []string{"1 hash(es) with no {SCHEME}"},
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

// TestPassdbDefaultScheme — the doctor has to read what the passdb actually says,
// because the panel writes no `scheme=` at all when it could not ask the host
// which schemes it has (see reconciler.RenderDovecotUsersConf). Assuming the
// panel's preferred scheme there would report working mailboxes as broken, and
// assuming nothing would report broken ones as fine.
func TestPassdbDefaultScheme(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "the passdb names one",
			content: "passdb {\n  driver = passwd-file\n  args = username_format=%u scheme=ssha512 /etc/dovecot/users\n}\n",
			want:    "SSHA512",
		},
		{
			name:    "the passdb names none, so Dovecot's own default applies",
			content: "passdb {\n  driver = passwd-file\n  args = username_format=%u /etc/dovecot/users\n}\n",
			want:    dovecot.DefaultPassdbScheme,
		},
		{
			name: "a commented-out argument is not an argument",
			content: "passdb {\n  # args = username_format=%u scheme=ARGON2ID /etc/dovecot/users\n" +
				"  args = username_format=%u /etc/dovecot/users\n}\n",
			want: dovecot.DefaultPassdbScheme,
		},
		{
			name:    "the file is not there at all",
			content: "",
			want:    dovecot.DefaultPassdbScheme,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.content != "" {
				if err := os.MkdirAll(filepath.Join(dir, "conf.d"), 0o755); err != nil {
					t.Fatalf("mkdir conf.d: %v", err)
				}
				path := filepath.Join(dir, "conf.d", "10-auth-mailx.conf")
				if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
					t.Fatalf("write %s: %v", path, err)
				}
			}

			if got := passdbDefaultScheme(dir); got != tc.want {
				t.Errorf("passdbDefaultScheme = %q, want %q", got, tc.want)
			}
		})
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

// TestUnprovenHashes — the second half of the scheme check, and the one that
// judging by scheme name cannot do: `doveadm pw -l` lists CRYPT on every build,
// so a {CRYPT} row looks verifiable while the hash inside it may be one this
// host's crypt() refuses. That is the login failure this release is about — a
// correct password and "code=temp_fail" — and the panel can only answer it
// honestly by saying it never proved that line.
func TestUnprovenHashes(t *testing.T) {
	cases := []struct {
		name   string
		counts map[string]int
		want   []string
	}{
		{
			name:   "a passwd-file the panel wrote",
			counts: map[string]int{"ARGON2ID": 3, "SSHA512": 1},
		},
		{
			name:   "one adopted system mailbox",
			counts: map[string]int{"ARGON2ID": 3, "CRYPT": 1},
			want:   []string{"1 {CRYPT} hash(es)"},
		},
		{
			name:   "several, reported in a stable order",
			counts: map[string]int{"CRYPT": 2},
			want:   []string{"2 {CRYPT} hash(es)"},
		},
		{
			name:   "an unprefixed hash is not a {CRYPT} row",
			counts: map[string]int{"(default)": 2},
		},
		{
			name:   "an empty passwd-file",
			counts: map[string]int{},
		},
	}

	for _, tc := range cases {
		got := unprovenHashes(tc.counts)
		joined := strings.Join(got, ", ")
		for _, want := range tc.want {
			if !strings.Contains(joined, want) {
				t.Errorf("%s: %q not reported in %v", tc.name, want, got)
			}
		}
		if len(tc.want) == 0 && len(got) != 0 {
			t.Errorf("%s: reported %v, want nothing", tc.name, got)
		}
	}
}

// TestPasswdFileAccess — 0640 root:dovecot is the pairing the reconciler writes
// (see reconciler.dovecotPasswdOwner). The two ways to get it wrong are a file
// only root can read, which the auth process cannot open at all, and one every
// user on the server can read, which hands out a password hash per mailbox.
func TestPasswdFileAccess(t *testing.T) {
	cases := []struct {
		name   string
		mode   os.FileMode
		status Status
	}{
		{name: "0640 root:dovecot", mode: 0o640, status: OK},
		{name: "0440, group-readable without the write bit", mode: 0o440, status: OK},
		{name: "0600 root:root, which is what this used to be", mode: 0o600, status: Warn},
		{name: "0644, which shows every hash to every user", mode: 0o644, status: Warn},
		{name: "0666, which is what a Windows checkout reports", mode: 0o666, status: Warn},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := passwdFileAccess("/etc/dovecot/users", tc.mode)

			if got.Name != "dovecot passwd file" {
				t.Errorf("name = %q, want it named", got.Name)
			}
			if got.Status != tc.status {
				t.Errorf("status = %q (%s), want %q", got.Status, got.Detail, tc.status)
			}
			if tc.status == Warn && got.Hint == "" {
				t.Error("a warning with no hint is one the operator cannot act on")
			}
			if tc.status == OK && got.Command != "" {
				t.Errorf("command = %q on a healthy file, want none", got.Command)
			}
		})
	}
}

// TestPasswdFileCheckWithNothingToCheck — a panel with no mailboxes yet has no
// passwd-file, and that is not something to report as a problem: the sync writes
// it as soon as there is a mailbox to render.
func TestPasswdFileCheckWithNothingToCheck(t *testing.T) {
	opts := Options{Config: &config.Config{
		Mail: config.MailConfig{DovecotConfDir: t.TempDir()},
	}}

	if got := passwdFileCheck(opts); got.Name != "dovecot passwd file" || got.Status != Info {
		t.Errorf("passwdFileCheck with no file = %+v, want an info check", got)
	}

	// With no config at all there is no path to look at, and a guess would be
	// worse than saying nothing.
	if got := passwdFileCheck(Options{}); got.Name != "" {
		t.Errorf("passwdFileCheck with no config = %+v, want no check", got)
	}
}
