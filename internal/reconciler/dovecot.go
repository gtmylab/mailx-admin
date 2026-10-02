package reconciler

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/dovecot"
	"github.com/gtmylab/mailx-admin/internal/models"
)

// RenderDovecotPasswd produces /etc/dovecot/users — the passwd-file used by
// Dovecot's passdb and userdb. Format:
//
//	alice@example.com:{ARGON2ID}$argon2id$...:5000:5000::/var/mail/vhosts/example.com/alice::userdb_quota_rule=*:storage=1024M
//	test1@example.com:{CRYPT}$6$...:1000:1000::/home/test1::userdb_quota_rule=*:storage=2048M
//
// One file, one passdb, two shapes of mailbox:
//
//   - a virtual mailbox is owned by the vmail account and lives under
//     virtual_mailbox_base (models.VmailBase);
//   - a system mailbox belongs to a real Unix account, keeps that account's
//     uid/gid, and its mail sits in /home/<user>/Maildir.
//
// The uid/gid/home on each line override the userdb defaults in
// RenderDovecotUsersConf, which is what lets both kinds share one passdb.
// Rendering a system mailbox with 5000:5000 would leave Dovecot unable to open
// a maildir owned by the account — the login succeeds and every folder then
// fails with "Permission denied".
//
// The passdb's `scheme=ARGON2ID` argument is only the default for a password
// with no {SCHEME} prefix. Imported system mailboxes carry {CRYPT}<hash> and are
// verified with the system's crypt() (yescrypt/sha512), which is exactly why
// they are stored in that scheme and not re-hashed with argon2id.
//
// Quota is enforced via the userdb extra field:
// `userdb_quota_rule=*:storage=1024M`.
func RenderDovecotPasswd(snap *models.Snapshot) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n")
	b.WriteString("# Format: user:password:uid:gid:gecos:home:shell:extra\n")
	b.WriteString("# uid/gid/home are the account's own for a system mailbox\n")
	b.WriteString("# (kind=system in the panel), the vmail account under\n")
	b.WriteString("# virtual_mailbox_base for a virtual one.\n\n")

	lines := make([]string, 0, len(snap.Users))
	for _, u := range snap.Users {
		extra := fmt.Sprintf("userdb_quota_rule=*:storage=%dM", u.QuotaMB)
		line := fmt.Sprintf("%s:%s:%d:%d::%s::%s",
			u.Email,
			u.PasswordHash,
			u.DeliveryUID(),
			u.DeliveryGID(),
			u.MailHome(),
			extra,
		)
		lines = append(lines, line)
	}
	sort.Strings(lines)

	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.Bytes()
}

// RenderDovecotQuotaConf produces /etc/dovecot/conf.d/90-quota.conf.
func RenderDovecotQuotaConf() []byte {
	return []byte(`# Managed by mailx-admin — DO NOT EDIT
plugin {
  quota = maildir:User quota
  quota_rule = *:storage=1G
  quota_rule2 = Trash:storage=+100M
  quota_grace = 10%%
  quota_status_success = DUNNO
  quota_status_nouser = DUNNO
  quota_status_overquota = "552 5.2.2 Mailbox is full"
}

service quota-status {
  executable = quota-status -p postfix
  inet_listener {
    port = 12340
  }
  client_limit = 1
}

protocol imap {
  mail_plugins = $mail_plugins quota imap_quota
}
protocol pop3 {
  mail_plugins = $mail_plugins quota
}
`)
}

// RenderDovecotUsersConf produces the drop-in that tells Dovecot to use
// our passwd-file for authentication.
//
// `default_fields` is only a fallback: every line of the passwd-file carries its
// own uid/gid/home, so a system mailbox keeps its real account while a virtual
// one falls back to the vmail account under virtual_mailbox_base.
//
// scheme is the passdb's default for a hash with no {SCHEME} prefix. The panel
// writes the prefix on every hash it creates, so this only matters for a line an
// operator added by hand — but it must not be a name this Dovecot was not built
// with. It comes from resolveScheme (internal/dovecot.Resolve), which asks the
// local Dovecot what it supports.
//
// When nobody could answer — "" or "auto", which is the caller saying it could
// not ask — no scheme= is written at all rather than a guess. Dovecot then
// verifies a prefix-less hash with its own compiled-in default
// (dovecot.DefaultPassdbScheme, CRYPT), which is what an /etc/shadow-style line
// expects; argon2id written there would be a default half the world's builds
// cannot resolve.
//
// A placeholder must never reach the file: "auto" and "AUTO" are the panel's way
// of saying "ask the local Dovecot", and `scheme=auto` would hand Dovecot a name
// no build has. Names that are written are upper-cased, because that is the
// spelling `doveadm pw -l` prints and the one Dovecot matches against.
func RenderDovecotUsersConf(passwdFilePath, scheme string) []byte {
	passdbArgs := fmt.Sprintf("username_format=%%u %s", passwdFilePath)
	if !resolvesToHostScheme(scheme) {
		passdbArgs = fmt.Sprintf("username_format=%%u scheme=%s %s",
			strings.ToUpper(strings.TrimSpace(scheme)), passwdFilePath)
	}

	return []byte(fmt.Sprintf(`# Managed by mailx-admin — DO NOT EDIT
passdb {
  driver = passwd-file
  # args: username_format, plus a scheme only when one this Dovecot was built
  # with is known. Without it Dovecot uses its own default (%s) for a hash with no
  # {SCHEME} prefix — every line the panel writes carries its own {SCHEME}
  # anyway: an imported system mailbox keeps its {CRYPT} hash, which is checked
  # with crypt() rather than with this default.
  args = %s
}

userdb {
  driver = passwd-file
  args = username_format=%%u %s
  default_fields = uid=5000 gid=5000 home=/var/mail/vhosts/%%d/%%n
}

auth_mechanisms = plain login
# Plaintext auth has to stay allowed: Roundcube logs in to Dovecot over plain
# IMAP on localhost:143 (default_host = localhost, no TLS), which is why the
# installer writes disable_plaintext_auth = no. "yes" here would disable the only
# two mechanisms Roundcube offers and refuse every webmail login.
disable_plaintext_auth = no
`, dovecot.DefaultPassdbScheme, passdbArgs, passwdFilePath))
}
