package execx

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The tests below run the minimal shell of the host: `sh` on the Linux CI that
// ships the panel, `cmd.exe` on a developer's Windows machine, so a regression
// in execx is caught before it reaches either.

// failingCommand writes to stderr and exits non-zero.
func failingCommand() (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd.exe", []string{"/c", "echo managed-file-is-broken 1>&2 & exit /b 3"}
	}
	return "sh", []string{"-c", "echo managed-file-is-broken 1>&2; exit 3"}
}

// sleepingCommand ignores cancellation for far longer than any test budget.
func sleepingCommand() (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd.exe", []string{"/c", "ping -n 60 127.0.0.1 >nul"}
	}
	return "sh", []string{"-c", "sleep 60"}
}

// sleepingCommandWithChild has the shape of the v1.0.4 hang: a child that
// outlives the process we started, holding the stdout pipe open. Killing only
// the parent leaves Wait blocked on that pipe.
func sleepingCommandWithChild() (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd.exe", []string{"/c", "ping -n 60 127.0.0.1 >nul & ping -n 60 127.0.0.1 >nul"}
	}
	return "sh", []string{"-c", "sleep 60 & sleep 60"}
}

// TestRunReturnsCommandOutput — the error an operator sees has to name the
// command and carry what it printed; `postfix check` explains itself on stderr
// and nowhere else.
func TestRunReturnsCommandOutput(t *testing.T) {
	name, args := failingCommand()

	err := Run(context.Background(), 10*time.Second, name, args...)
	if err == nil {
		t.Fatal("Run returned nil for a command that exited non-zero")
	}
	if !strings.Contains(err.Error(), "managed-file-is-broken") {
		t.Errorf("error %q does not carry the command's output", err)
	}
	if !strings.Contains(err.Error(), name) {
		t.Errorf("error %q does not name the command that failed", err)
	}
}

// TestRunKillsACommandThatIgnoresTheDeadline is the second half of the v1.0.4
// freeze: the request deadline killed the helper, but the helper's child kept
// the output pipe open, so CombinedOutput never returned and the reconcile
// (holding its SQLite transaction) never finished.
func TestRunKillsACommandThatIgnoresTheDeadline(t *testing.T) {
	name, args := sleepingCommandWithChild()

	start := time.Now()
	err := Run(context.Background(), 500*time.Millisecond, name, args...)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Run error = %v, want it to wrap ErrTimeout", err)
	}
	// The budget is 0.5s and WaitDelay is 3s, so anything near the helper's own
	// 60s means the group was not killed and Wait did not give up on the pipe.
	if elapsed > 15*time.Second {
		t.Errorf("Run took %s: the child outlived its deadline", elapsed)
	}
}

// TestRunHonoursTheCallerContext — cancelling the request (browser closed, the
// panel shutting down) has to end the call too, not just the deadline.
func TestRunHonoursTheCallerContext(t *testing.T) {
	name, args := sleepingCommand()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := Run(ctx, time.Minute, name, args...)

	if err == nil {
		t.Fatal("Run returned nil for a canceled context")
	}
	if errors.Is(err, ErrTimeout) {
		t.Errorf("Run reported a timeout for a cancellation: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("Run took %s after the context was canceled", elapsed)
	}
}

// TestBoundedBufferTruncates — a helper that keeps writing must not grow the
// panel's heap, and whatever it writes must still look like a successful write
// to io.Copy (the io.Writer contract), or exec.Cmd reports a bogus io error.
func TestBoundedBufferTruncates(t *testing.T) {
	var buf boundedBuffer
	chunk := []byte(strings.Repeat("x", 1024))

	writes := 0
	for written := 0; written < 64*1024; written += len(chunk) {
		n, err := buf.Write(chunk)
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if n != len(chunk) {
			t.Fatalf("Write returned %d, want %d", n, len(chunk))
		}
		writes++
	}
	if writes < 2 {
		t.Fatal("test did not write enough")
	}

	out := buf.Bytes()
	if len(out) < maxOutput {
		t.Errorf("captured %d bytes, want the buffer to fill up to %d", len(out), maxOutput)
	}
	if len(out) > maxOutput+128 {
		t.Errorf("captured %d bytes, want at most %d plus the elision notice", len(out), maxOutput)
	}
	if !strings.Contains(string(out), "elided") {
		t.Error("truncated output does not say how much was dropped")
	}
}

// TestOutputReturnsTheCommandOutput keeps the success path honest: callers use
// the error to decide what happened, and the output to explain it.
func TestOutputReturnsTheCommandOutput(t *testing.T) {
	var name string
	var args []string
	if runtime.GOOS == "windows" {
		name, args = "cmd.exe", []string{"/c", "echo ready"}
	} else {
		name, args = "sh", []string{"-c", "echo ready"}
	}

	out, err := Output(context.Background(), 10*time.Second, name, args...)
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if !strings.Contains(string(out), "ready") {
		t.Errorf("Output = %q, want it to contain the command's output", out)
	}
}
