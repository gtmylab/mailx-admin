package reconciler

import (
	"github.com/gtmylab/mailx-admin/internal/models"
	"github.com/gtmylab/mailx-admin/internal/sieve"
)

func RenderUserSieve(user models.User, rules []models.SieveRule) ([]byte, error) {
	script, err := sieve.Generate(rules, user.Email)
	if err != nil {
		return nil, err
	}
	return []byte(script), nil
}

// UserSievePath is the script the panel writes for one mailbox.
//
// It follows the mailbox's own home (models.User.MailHome), so a virtual
// mailbox keeps /var/mail/vhosts/<domain>/<user>/sieve and a system mailbox
// keeps /home/<user>/sieve. Hard-coding the vhosts path — which is what this
// did — writes a system account's Sieve script into a directory Dovecot never
// looks at, and the rules then simply never run.
func UserSievePath(user models.User) string {
	return user.MailHome() + "/sieve/managesieve.sieve"
}
