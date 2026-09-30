package reconciler

import (
	"context"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/gtmylab/mailx-admin/internal/models"
)

// maildirSpec is one directory the mail stack needs before it can deliver.
type maildirSpec struct {
	path string
	uid  int
	gid  int
	mode os.FileMode
	// owner is the human name of the account that gets the directory: "vmail"
	// or the mailbox's user name. Only used in operator-facing messages.
	owner string
}

// planMaildirs decides which directories every mailbox needs, who owns them and
// in which order they have to be created.
//
// The plan is a pure function on purpose. Creating the directories only happens
// on the server (it needs chown), while the plan is the part that can be wrong
// in an interesting way: a system mailbox planned under /var/mail/vhosts is
// invisible until delivery silently fails, and Dovecot refuses to open a maildir
// it does not own.
//
// Layout:
//
//	virtual  /var/mail/vhosts/<domain>                     vmail:vmail 0770
//	         /var/mail/vhosts/<domain>/<user>              vmail:vmail 0700
//	         /var/mail/vhosts/<domain>/<user>/Maildir/{cur,new,tmp}
//	         /var/mail/vhosts/<domain>/<user>/sieve
//	system   <home>/Maildir/{cur,new,tmp}                  <account>   0700
//	         <home>/sieve
//
// A system mailbox's home already exists — useradd created it — so only the
// maildir inside it is ours. Nothing in the installer ever created the
// per-mailbox directory for a virtual mailbox either, which is why a mailbox
// created in the panel could be listed, rendered and still not receive mail:
// virtual(8) needs a parent directory owned by vmail to write into.
func planMaildirs(snap *models.Snapshot) []maildirSpec {
	seen := map[string]bool{}
	var out []maildirSpec

	add := func(spec maildirSpec) {
		if spec.path == "" || seen[spec.path] {
			return
		}
		seen[spec.path] = true
		out = append(out, spec)
	}

	for _, u := range snap.Users {
		if u.Username == "" || !u.Active {
			continue
		}

		home := u.MailHome()
		uid, gid, owner := u.DeliveryUID(), u.DeliveryGID(), u.Username

		if !u.IsSystem() {
			// vmail owns the whole tree for a virtual mailbox. Postfix
			// creates the user's maildir itself, but only inside a domain
			// directory it is allowed to write to.
			uid, gid, owner = models.VmailUID, models.VmailGID, "vmail"
			add(maildirSpec{
				path: path.Dir(home), uid: uid, gid: gid,
				mode: 0o770, owner: owner,
			})
		}

		add(maildirSpec{path: home, uid: uid, gid: gid, mode: 0o700, owner: owner})

		maildir := path.Join(home, "Maildir")
		for _, sub := range []string{"", "cur", "new", "tmp"} {
			add(maildirSpec{
				path: path.Join(maildir, sub), uid: uid, gid: gid,
				mode: 0o700, owner: owner,
			})
		}

		// Dovecot's Sieve plugin keeps a user's scripts in ~/sieve, and the
		// panel writes its own rules next to them (see sieve.go).
		add(maildirSpec{
			path: path.Join(home, "sieve"), uid: uid, gid: gid,
			mode: 0o700, owner: owner,
		})
	}

	// Shallowest first: a child must never be created before its parent, or
	// the parent ends up root-owned and the mailbox stays undeliverable.
	sort.SliceStable(out, func(i, j int) bool {
		return pathDepth(out[i].path) < pathDepth(out[j].path)
	})
	return out
}

// pathDepth counts the components of a mail path.
//
// The paths here are always in the *server's* namespace ("/var/mail/vhosts/...",
// "/home/..."), never the build host's, so they use the slash-only `path`
// package rather than filepath: joining them with filepath would render
// backslashes on a Windows development machine and, worse, make the plan
// disagree with the vmailbox and passwd files that already say
// "/var/mail/vhosts".
func pathDepth(p string) int {
	return strings.Count(p, "/")
}

// ensureMaildirs materialises the plan. It returns what it had to create and the
// problems it could not solve.
//
// Failures are warnings, never errors. By the time this runs the config files
// are already written and valid; a directory the panel cannot create (a sync
// that runs unprivileged, a read-only /var/mail, a full disk) must not roll the
// sync back and leave the daemons unreloaded. The operator sees it in the
// dashboard's sync banner and in `mailx-admin doctor`.
func ensureMaildirs(ctx context.Context, snap *models.Snapshot) (created, warnings []string) {
	for _, spec := range planMaildirs(snap) {
		if ctx.Err() != nil {
			return created, warnings
		}

		if _, err := os.Stat(spec.path); err == nil {
			// Already there. Fix ownership if it drifted — a maildir copied
			// in by hand, or one an older version created root-owned, makes
			// Dovecot fail every login with "Permission denied" and gives the
			// operator nothing to go on.
			if err := claimDir(spec); err != nil {
				warnings = append(warnings, fmt.Sprintf("fix ownership of %s: %v", spec.path, err))
			}
			continue
		} else if !os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("stat %s: %v", spec.path, err))
			continue
		}

		if err := createDir(spec); err != nil {
			warnings = append(warnings, fmt.Sprintf("create %s: %v", spec.path, err))
			continue
		}
		created = append(created, spec.path)
	}
	return created, warnings
}
