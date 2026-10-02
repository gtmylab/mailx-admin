// Package execx runs the external helpers MailX depends on — postmap,
// `postfix check`, `doveconf -n`, `systemctl reload-or-restart`, `postqueue` —
// with the four guarantees the panel needs in order to stay responsive.
//
//   - A hard deadline, independent of the caller's context.
//   - The whole process group is killed on expiry, so a helper that spawns
//     children (postmap, `postfix check` runs postconf) cannot leave one behind
//     holding a lock on the file we are about to rewrite.
//   - WaitDelay, so Wait can never block forever on a pipe an orphan inherited.
//     This is the v1.0.4 bug: the request deadline killed `postmap`, but a
//     surviving child still held the output pipe, so CombinedOutput never
//     returned. The reconcile held its SQLite transaction, every later request
//     queued behind the single pooled connection, Apache timed out after 60s
//     and answered 502 until the service was restarted.
//   - Bounded output. A helper that streams endlessly writes into the void
//     instead of into the panel's heap.
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultTimeout is used when a caller passes a non-positive timeout.
	DefaultTimeout = 30 * time.Second

	// waitDelay bounds how long Wait may keep waiting for the output pipes once
	// the process has been killed. Without it, Wait inherits the lifetime of
	// whatever grandchild grabbed the pipe, which is unbounded.
	waitDelay = 3 * time.Second

	// maxOutput caps the captured stdout+stderr. Errors only ever quote a
	// trailing excerpt anyway; the cap exists so a runaway command cannot grow
	// the process without limit.
	maxOutput = 8 << 10
)

// ErrTimeout reports that the command did not finish inside its budget. It is
// wrapped, so callers test with errors.Is.
var ErrTimeout = errors.New("timed out")

// Run executes name with args and discards the output on success. On failure
// the returned error carries the command line and the captured output, which is
// what the panel shows the operator and what the reconciler logs.
func Run(ctx context.Context, timeout time.Duration, name string, args ...string) error {
	out, err := Output(ctx, timeout, name, args...)
	if err != nil {
		cmdline := strings.TrimSpace(name + " " + strings.Join(args, " "))
		if trailer := outputTrailer(out); trailer != "" {
			return fmt.Errorf("%s: %w\n%s", cmdline, err, trailer)
		}
		return fmt.Errorf("%s: %w", cmdline, err)
	}
	return nil
}

// Output executes name with args and returns the combined stdout+stderr of the
// command, truncated to maxOutput bytes.
func Output(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	return output(ctx, timeout, nil, name, args...)
}

// OutputStdin is Output, but it pipes data to the command's standard input
// first. It exists for the one helper that reads a secret from stdin rather than
// from argv — `doveadm pw -t`, which tests a password against a hash — so the
// secret never shows up in `ps`.
func OutputStdin(ctx context.Context, timeout time.Duration, stdin []byte, name string, args ...string) ([]byte, error) {
	return output(ctx, timeout, stdin, name, args...)
}

func output(ctx context.Context, timeout time.Duration, stdin []byte, name string, args ...string) ([]byte, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	prepareProcessGroup(cmd)
	// CommandContext only kills the process it started. Overriding Cancel lets
	// the whole group go, which is the difference between postmap dying and
	// postmap's child surviving to hold the postmap.db lock.
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = waitDelay

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	var buf boundedBuffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	err := cmd.Run()
	out := buf.Bytes()

	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			return out, fmt.Errorf("%w after %s", ErrTimeout, timeout)
		}
		// The caller's context (request deadline, shutdown) was canceled.
		return out, context.Canceled
	}
	if err != nil {
		return out, err
	}
	return out, nil
}

// outputTrailer renders the captured output for an error message, marking it as
// truncated when the buffer hit its cap.
func outputTrailer(out []byte) string {
	s := strings.TrimRight(string(out), " \t\r\n")
	if s == "" {
		return ""
	}
	return s
}

// boundedBuffer collects at most maxOutput bytes and counts the rest.
//
// cmd copies stdout and stderr from two different goroutines, so every method
// takes the lock; bytes.Buffer alone would race.
type boundedBuffer struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	dropped int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	n := len(p) // claim the whole write, whatever we keep
	if room := maxOutput - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.dropped += len(p) - room
			p = p[:room]
		}
		_, _ = b.buf.Write(p)
		return n, nil
	}
	b.dropped += len(p)
	return n, nil
}

// Bytes returns what was captured. "Bytes" is what exec.Cmd's writers expect,
// so the name is part of the interface, not a preference.
func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]byte, b.buf.Len())
	copy(out, b.buf.Bytes())
	if b.dropped > 0 {
		out = append(out, []byte(fmt.Sprintf("\n... (%d more bytes of output elided)", b.dropped))...)
	}
	return out
}
