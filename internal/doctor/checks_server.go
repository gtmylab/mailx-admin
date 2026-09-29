package doctor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/gtmylab/mailx-admin/internal/execx"
	"github.com/gtmylab/mailx-admin/internal/seed"
)

// serverStateCheck compares the mailboxes and domains in the server's own
// configuration with the panel's. This is the "I created a user with useradd and
// the panel does not show it" answer: the panel lists what is in its database,
// and everything else has to be imported.
func serverStateCheck(ctx context.Context, opts Options) Check {
	if opts.Config == nil || opts.Store == nil {
		return Check{}
	}

	found, err := seed.Scan(seed.Options{
		PostfixConfDir:    opts.Config.Mail.PostfixConfDir,
		DovecotConfDir:    opts.Config.Mail.DovecotConfDir,
		OpenDKIMDir:       opts.Config.Mail.OpenDKIMDir,
		PrimaryDomainFile: opts.Config.Mail.PrimaryDomainFile,
	})
	if err != nil {
		return Check{Name: "server configuration", Status: Warn, Detail: err.Error()}
	}

	plan, err := seed.Plan(ctx, opts.Store, found)
	if err != nil {
		return Check{Name: "server configuration", Status: Warn, Detail: err.Error()}
	}

	detail := fmt.Sprintf("found %d domain(s), %d mailbox(es), %d alias(es) in Postfix/Dovecot",
		len(found.Domains), len(found.Users), len(found.Aliases))
	if plan.Empty() {
		return Check{Name: "server configuration", Status: OK, Detail: detail + "; all of them are in the panel"}
	}
	return Check{
		Name:   "server configuration",
		Status: Warn,
		Detail: fmt.Sprintf("%s; %s not in the panel, and the next sync would drop %s",
			detail,
			plural(plan.Total(), "1 entry is", fmt.Sprintf("%d entries are", plan.Total())),
			plural(plan.Total(), "it", "them")),
		Hint:    "import them instead of recreating them by hand",
		Command: "mailx-admin adopt",
	}
}

func serviceCheck(ctx context.Context, opts Options) Check {
	if opts.SkipServices {
		return Check{}
	}

	if _, err := exec.LookPath("systemctl"); err != nil {
		return Check{
			Name:   "services",
			Status: Warn,
			Detail: "systemctl is not available on this host",
			Hint:   "run doctor on the mail server itself",
		}
	}

	var inactive []string
	for _, n := range []string{"postfix", "dovecot", "opendkim"} {
		out, err := execx.Output(ctx, 10*time.Second, "systemctl", "is-active", n)
		state := strings.TrimSpace(string(out))
		if err != nil || state != "active" {
			inactive = append(inactive, n+": "+state)
		}
	}
	if len(inactive) > 0 {
		return Check{
			Name:    "services",
			Status:  Fail,
			Detail:  strings.Join(inactive, ", "),
			Hint:    "the configuration cannot take effect while a daemon is down",
			Command: "systemctl status postfix dovecot opendkim",
		}
	}
	return Check{Name: "services", Status: OK, Detail: "postfix, dovecot and opendkim are active"}
}

// lastSyncCheck reports what the panel's own sync history says, which is the
// first thing to look at when "the panel did nothing" after a change.
func lastSyncCheck(ctx context.Context, opts Options) Check {
	if opts.LastSync == nil {
		return Check{}
	}
	s := opts.LastSync

	switch s.Status {
	case "ok":
		return Check{
			Name:   "last sync",
			Status: OK,
			Detail: fmt.Sprintf("%s (%s), no errors", s.StartedAt.Format(time.RFC1123), s.Trigger),
		}
	case "running":
		return Check{
			Name:   "last sync",
			Status: Info,
			Detail: fmt.Sprintf("still running, started %s (%s)", s.StartedAt.Format(time.RFC1123), s.Trigger),
		}
	default:
		return Check{
			Name:    "last sync",
			Status:  Fail,
			Detail:  fmt.Sprintf("failed at %s (%s): %s", s.StartedAt.Format(time.RFC1123), s.Trigger, s.Error),
			Hint:    "the panel's changes are in the database but may not have reached the daemons",
			Command: "systemctl status mailx-admin",
		}
	}
}

func roundcubeNote() Check {
	return Check{
		Name:   "roundcube data",
		Status: Info,
		Detail: "importing Roundcube's MySQL address books and identities is not part of this release",
		Hint:   "mailboxes, domains and aliases are imported; Roundcube's own tables are left untouched",
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
