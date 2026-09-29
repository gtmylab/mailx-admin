//go:build unix

package execx

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// prepareProcessGroup puts the child into a fresh process group so the panel can
// signal the child and every grandchild it spawns in one call. `postmap` and
// `postfix check` fork helpers; killing only the parent leaves them behind,
// holding the very database file we are rewriting.
func prepareProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killGroup kills the child's whole process group. A negative pid means "every
// process in the group", which is what Setpgid above set up.
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		// Cancel can run before Start finished; there is nothing to kill.
		return os.ErrProcessDone
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			// Already gone: not a failure, and reporting it would make exec.Cmd
			// surface a bogus error instead of the real one.
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}
