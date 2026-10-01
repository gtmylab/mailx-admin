package roundcube

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The installer lives in this repository as Mailx-Installer and ships as its own
// release asset, so this is the one place its Roundcube side can be checked
// against the panel: it shares no code with anything in this module.

// installerSource reads the shipped installer.
func installerSource(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "Mailx-Installer"))
	if err != nil {
		t.Fatalf("read the shipped installer: %v", err)
	}
	return string(raw)
}

// installerFunction returns one shell function's body.
func installerFunction(t *testing.T, src, name string) string {
	t.Helper()

	marker := "\n" + name + "() {\n"
	start := strings.Index(src, marker)
	if start < 0 {
		t.Fatalf("Mailx-Installer no longer defines %s()", name)
	}

	rest := src[start+len(marker):]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatalf("%s() is never closed", name)
	}
	return rest[:end]
}

// installerRoundcubeConfigKeys is the exact set of Roundcube `$config` keys the
// installer writes, in the order it writes them.
//
// It is pinned because one key of this set is enough to refuse every webmail
// login on a fresh host: v1.0.9 added `username_domain` (it rewrites the login
// name before Dovecot ever sees it) together with the Roundcube 1.6 spellings
// `imap_host`/`smtp_host` (which take precedence over `default_host` wherever they
// exist), and in v1.0.10 neither a user the installer created nor one created in
// the panel could log in. Changing this set is therefore a change to whether
// webmail works after an install, and it has to be a deliberate edit here — with
// `verify_login` run against a real server afterwards.
var installerRoundcubeConfigKeys = []string{
	"db_dsnw",      // the Roundcube database
	"default_host", // the IMAP server a login goes to
	"smtp_server",  // and the one it sends through
	"smtp_port",
	"support_url",
	"mail_domain", // shown in the UI; not what completes a login name
	"des_key",
}

// installerRoundcubeConfigBlock returns the section of
// install_roundcube_application that writes config.inc.php, comments included.
func installerRoundcubeConfigBlock(t *testing.T, src string) string {
	t.Helper()

	lines := strings.Split(src, "\n")
	call := regexp.MustCompile(`rc_set_config config/config\.inc\.php`)

	start, end := -1, -1
	for i, line := range lines {
		if !call.MatchString(line) {
			continue
		}
		if start < 0 {
			start = i
		}
		end = i
	}
	if start < 0 {
		t.Fatal("Mailx-Installer no longer writes Roundcube's config.inc.php through rc_set_config")
	}

	// Walk back over the comment block that introduces the calls, so the
	// assertions below see the block as a whole.
	for start > 0 && strings.HasPrefix(strings.TrimSpace(lines[start-1]), "#") {
		start--
	}
	return strings.Join(lines[start:end+1], "\n")
}

// TestInstallerRoundcubeConfigKeys — the keys the installer puts into Roundcube's
// config are the login contract between a fresh host and Dovecot.
func TestInstallerRoundcubeConfigKeys(t *testing.T) {
	block := installerRoundcubeConfigBlock(t, installerSource(t))

	var got []string
	for _, m := range regexp.MustCompile(`rc_set_config config/config\.inc\.php ([a-z_]+) `).
		FindAllStringSubmatch(block, -1) {
		got = append(got, m[1])
	}

	if strings.Join(got, ",") != strings.Join(installerRoundcubeConfigKeys, ",") {
		t.Errorf("the installer's Roundcube config keys changed:\n got: %v\nwant: %v\n\n"+
			"username_domain rewrites the login name before Dovecot sees it, and imap_host "+
			"overrides default_host — that pair is what refused every webmail login in v1.0.10. "+
			"Re-adding either is only safe together with a login test on a real host: "+
			"verify_login in the installer, run against both kinds of mailbox.",
			got, installerRoundcubeConfigKeys)
	}

	// The group above, spelled out: it must not come back through another
	// mechanism either (a second rc_set_config call, a sed, a here-document).
	// Comment lines are skipped on purpose — that is where the note saying why
	// these keys must not return lives, and it has to be able to name them.
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, forbidden := range []string{"username_domain", "imap_host", "smtp_host"} {
			if strings.Contains(line, forbidden) {
				t.Errorf("the installer writes %q again: every webmail login refused in v1.0.10 "+
					"traces to this group of keys — line: %s", forbidden, line)
			}
		}
	}
}

// TestInstallerRotatesDesKeyOnlyWhenEmpty — Roundcube's sample ships a public
// des_key, so it has to be replaced; rotating it on every install run (v1.0.9)
// instead logs every user out and invalidates every IMAP password Roundcube has
// stored, which looks exactly like a webmail regression.
func TestInstallerRotatesDesKeyOnlyWhenEmpty(t *testing.T) {
	lines := strings.Split(installerRoundcubeConfigBlock(t, installerSource(t)), "\n")

	desLine := -1
	for i, line := range lines {
		if strings.Contains(line, "rc_set_config config/config.inc.php des_key ") {
			desLine = i
			break
		}
	}
	if desLine < 0 {
		t.Fatal("the installer no longer sets des_key, so Roundcube keeps the sample's public key")
	}

	guarded := false
	for _, line := range lines[:desLine] {
		if strings.Contains(line, "grep") && strings.Contains(line, "des_key") {
			guarded = true
		}
	}
	if !guarded {
		t.Error("des_key is written unconditionally: rotating it on every run logs every user out " +
			"and drops every stored IMAP password (v1.0.9 did this)")
	}
}

// TestInstallerVerifiesEachNewLogin — the reason the webmail regression of
// v1.0.9/v1.0.10 reached users at all: nothing in the installer ever performed a
// login. The accounts were created, the welcome mail went out, and the failure
// was only visible in Roundcube.
func TestInstallerVerifiesEachNewLogin(t *testing.T) {
	src := installerSource(t)

	if !strings.Contains(src, "\nverify_login() {\n") {
		t.Error("Mailx-Installer defines no verify_login(): nothing proves a mailbox it just " +
			"created can actually log in")
	}
	if !strings.Contains(src, "doveadm auth test") {
		t.Error("Mailx-Installer never runs `doveadm auth test`, the only check that walks the " +
			"same passdb Dovecot's IMAP login walks")
	}

	// add_roundcube_user is where a mailbox and its password are handed to a
	// person, so it is where the check has to run — before the welcome mail,
	// because the mail names the login the check just proved.
	body := installerFunction(t, src, "add_roundcube_user")
	checked, mailed := strings.Index(body, "verify_login "), strings.Index(body, "send_welcome_email")
	if checked < 0 {
		t.Error("add_roundcube_user does not call verify_login: a password this Dovecot cannot " +
			"verify still reaches the user as \"login failed\" in webmail")
	}
	if mailed < 0 {
		t.Error("add_roundcube_user no longer sends the welcome mail, so the login check before " +
			"it cannot be reached")
	}
	if checked >= 0 && mailed >= 0 && checked > mailed {
		t.Error("add_roundcube_user sends the welcome mail before verify_login runs, so the " +
			"credentials go out untested")
	}
}
