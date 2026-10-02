package reconciler

import (
	"os/user"
	"strconv"
)

// dovecotPasswdOwner is the ownership Dovecot's passwd-file needs: root's uid,
// and the gid of the `dovecot` group.
//
// Why it is not "whatever we are running as": Dovecot's auth process — the one
// that opens the passdb file — drops to the unprivileged `dovecot` user
// (default_internal_user) before it reads anything. A passwd-file the panel
// wrote 0600 root:root is a file that process cannot open, and the failure it
// produces names neither the file nor the permissions: the login is refused, or
// the passdb fails to load and every login is refused with it.
//
// 0640 root:dovecot is the pairing this owner goes with: readable by root and by
// the auth process, and by nobody else — the file holds every mailbox' password
// hash, so 0644 would be a different bug.
//
// A nil result means "do not touch the ownership", which is the honest answer on
// a host with no `dovecot` group and on anything that is not a mail server (the
// test suite, a developer's laptop, Windows). The file is then written with the
// mode alone, exactly as it always was; doctor reports the resulting file's
// readability (see doctor.passwdFileCheck).
func dovecotPasswdOwner() *Ownership {
	group, err := user.LookupGroup("dovecot")
	if err != nil {
		return nil
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		// A group whose gid is not a number is a host we do not understand;
		// guessing 0 here would hand the file to root's group.
		return nil
	}
	return &Ownership{UID: 0, GID: gid}
}
