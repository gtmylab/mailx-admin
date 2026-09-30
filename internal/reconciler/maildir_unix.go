//go:build unix

package reconciler

import (
	"os"
	"syscall"
)

// createDir creates one directory of the plan with the ownership mail delivery
// needs. MkdirAll covers the case where the whole /var/mail/vhosts tree is
// missing (a panel installed on a server whose vmail account was never set up).
//
// The chown is not optional: root's default umask creates the directory as
// root:root, and neither Postfix (uid 5000 or the account's uid) nor Dovecot can
// write into a root-owned maildir.
func createDir(spec maildirSpec) error {
	if err := os.MkdirAll(spec.path, spec.mode); err != nil {
		return err
	}
	return os.Chown(spec.path, spec.uid, spec.gid)
}

// claimDir re-applies the planned ownership to a directory that already exists,
// and does nothing while it is already correct — the common case, and the one
// that must not turn every sync into a tree walk of chown syscalls.
func claimDir(spec maildirSpec) error {
	fi, err := os.Stat(spec.path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// Not a platform we know how to inspect; leave it alone rather than
		// chown blindly.
		return nil
	}
	if int(st.Uid) == spec.uid && int(st.Gid) == spec.gid {
		return nil
	}
	return os.Chown(spec.path, spec.uid, spec.gid)
}
