//go:build !unix

package execx

import (
	"os"
	"os/exec"
)

// prepareProcessGroup is the non-unix fallback: Windows has no process groups to
// signal, and SysProcAttr has no Setpgid field there.
func prepareProcessGroup(cmd *exec.Cmd) {}

// killGroup kills the child process. Grandchildren are out of reach on this
// platform, but WaitDelay in Output still bounds how long Wait can block on a
// pipe they inherited, which is the failure that mattered.
func killGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	return cmd.Process.Kill()
}
