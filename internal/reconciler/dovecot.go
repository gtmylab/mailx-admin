package reconciler

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// RenderDovecotPasswd produces /etc/dovecot/users — the passwd-file used by
// Dovecot's passdb. Format:
//
//	alice@example.com:{ARGON2ID}$argon2id$...:5000:5000::/var/mail/vhosts/example.com/alice::
//
// Quota is enforced via the `userdb` extra field: `userdb_quota_rule=*:storage=1024M`
func RenderDovecotPasswd(snap *models.Snapshot) []byte {
	var b bytes.Buffer
	b.WriteString("# Managed by mailx-admin — DO NOT EDIT\n")
	b.WriteString("# Format: user:password:uid:gid:gecos:home:shell:extra\n\n")

	lines := make([]string, 0, len(snap.Users))
	for _, u := range snap.Users {
		home := fmt.Sprintf("/var/mail/vhosts/%s/%s", u.DomainName, u.Username)
		extra := fmt.Sprintf("userdb_quota_rule=*:storage=%dM", u.QuotaMB)
		line := fmt.Sprintf("%s:%s:5000:5000::%s::%s",
			u.Email,
			u.PasswordHash,
			home,
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
func RenderDovecotUsersConf(passwdFilePath string) []byte {
	return []byte(fmt.Sprintf(`# Managed by mailx-admin — DO NOT EDIT
passdb {
  driver = passwd-file
  args = username_format=%%u scheme=ARGON2ID %s
}

userdb {
  driver = passwd-file
  args = username_format=%%u %s
  default_fields = uid=5000 gid=5000 home=/var/mail/vhosts/%%d/%%n
}

auth_mechanisms = plain login
disable_plaintext_auth = yes
`, passwdFilePath, passwdFilePath))
}
