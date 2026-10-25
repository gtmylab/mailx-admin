package reconciler

import (
	"context"
	"fmt"
	"os"

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

// sieveOwner is the ownership a managed Sieve script has to carry: the
// mailbox's own delivery account, which is vmail (5000) for a virtual mailbox
// and the real account's uid/gid for a system one.
//
// It is not cosmetic. managesieved opens the script as that account, and the
// LMTP/Sieve plugin reads it during delivery as the same one; a 0600
// root:root script is one both of them get EACCES on. The visible symptom is
// "your filters do nothing" in webmail, with nothing in the panel to explain
// it --  the file is there, it just is not readable by the daemon that has to
// run it.
//
// Unlike dovecotPasswdOwner/opendkimOwner this never returns nil: the uid/gid
// come from the model (models.User.DeliveryUID/DeliveryGID), so the answer is
// the same on a Windows development machine as on the server.
func sieveOwner(user models.User) *Ownership {
	return &Ownership{UID: user.DeliveryUID(), GID: user.DeliveryGID()}
}

// sieveScriptSpec is one managed script that has to be owned by its mailbox's
// delivery account.
type sieveScriptSpec struct {
	path string
	uid  int
	gid  int
}

// planSieveOwnership lists the managed scripts a snapshot implies: one per
// mailbox that has rules, exactly as the renderer in reconciler.go emits them.
//
// It is a pure function for the same reason planMaildirs and
// planDKIMKeyOwnership are: the interesting mistakes (a system mailbox's script
// planned under /var/mail/vhosts, uid 5000 for an account that is not vmail) are
// invisible at runtime until nothing happens, and are cheap to assert here.
func planSieveOwnership(snap *models.Snapshot) []sieveScriptSpec {
	var out []sieveScriptSpec
	for _, u := range snap.Users {
		if len(snap.SieveRules[u.ID]) == 0 {
			continue
		}
		owner := sieveOwner(u)
		out = append(out, sieveScriptSpec{
			path: UserSievePath(u),
			uid:  owner.UID,
			gid:  owner.GID,
		})
	}
	return out
}

// ensureSieveOwnership heals managed scripts written before the reconciler set
// an owner on them.
//
// WriteFileOwned only touches a file whose *content* changed, so an existing
// 0600 root:root script would stay root:root forever: every sync would report
// it "unchanged" and move on. Re-applying mode and owner on every reconcile is
// what makes an already-broken install heal on the next sync instead of
// staying broken until somebody deletes the file by hand.
//
// Failures are warnings, never errors: the configuration is already written and
// valid, and a panel that cannot chown must not roll the sync back. The
// operator sees it in the sync banner and in `mailx-admin doctor`.
func ensureSieveOwnership(ctx context.Context, snap *models.Snapshot) []string {
	var warnings []string
	for _, spec := range planSieveOwnership(snap) {
		if ctx.Err() != nil {
			return warnings
		}

		fi, err := os.Stat(spec.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf("stat %s: %v", spec.path, err))
			continue
		}
		if fi.IsDir() {
			// Not our file; leave it alone rather than chmod a directory to
			// a file's mode.
			continue
		}

		if err := os.Chmod(spec.path, 0o600); err != nil {
			warnings = append(warnings, fmt.Sprintf("chmod %s: %v", spec.path, err))
			continue
		}
		if err := os.Chown(spec.path, spec.uid, spec.gid); err != nil {
			warnings = append(warnings, fmt.Sprintf("chown %s: %v", spec.path, err))
		}
	}
	return warnings
}
