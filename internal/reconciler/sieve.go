package reconciler

import (
	"fmt"

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

func UserSievePath(user models.User) string {
	return fmt.Sprintf("/var/mail/vhosts/%s/%s/sieve/managesieve.sieve",
		user.DomainName, user.Username)
}
