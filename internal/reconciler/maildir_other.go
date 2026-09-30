//go:build !unix

package reconciler

import (
	"fmt"
	"runtime"
)

// createDir refuses to create mail directories off Unix.
//
// This is not laziness: a maildir is only usable by the mail stack when it is
// owned by the account that delivers into it, and there is no chown here. Making
// the directory anyway would hand the operator a tree that looks right and
// delivers nowhere — the failure mode this whole change exists to remove. Saying
// so turns it into a warning the dashboard shows. (execx_other.go makes the same
// split for process groups.)
func createDir(spec maildirSpec) error {
	return fmt.Errorf("creating mail directories requires ownership control, which %s does not have; run this on the mail server", runtime.GOOS)
}

// claimDir has nothing to re-apply where there is no ownership, so a directory
// that exists is left as it is.
func claimDir(spec maildirSpec) error { return nil }
