package reconciler

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFile_Create(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	change, err := WriteFile(path, []byte("hello"), 0o644, false)
	if err != nil {
		t.Fatal(err)
	}
	if change.Action != "create" {
		t.Errorf("want create, got %s", change.Action)
	}
	if got, _ := os.ReadFile(path); string(got) != "hello" {
		t.Errorf("content mismatch: %s", got)
	}
}

func TestWriteFile_UnchangedDoesNotTouch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	if _, err := WriteFile(path, []byte("hello"), 0o644, false); err != nil {
		t.Fatal(err)
	}

	info1, _ := os.Stat(path)

	change, err := WriteFile(path, []byte("hello"), 0o644, false)
	if err != nil {
		t.Fatal(err)
	}
	if change.Action != "unchanged" {
		t.Errorf("want unchanged, got %s", change.Action)
	}

	info2, _ := os.Stat(path)
	if !info1.ModTime().Equal(info2.ModTime()) {
		t.Errorf("mtime changed on identical content")
	}
}

func TestWriteFile_DryRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	change, err := WriteFile(path, []byte("hello"), 0o644, true)
	if err != nil {
		t.Fatal(err)
	}
	if change.Action != "create" {
		t.Errorf("want create, got %s", change.Action)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("dry run must not create file")
	}
}

// TestWriteFile_DryRunCarriesContentWhenNothingChanges is the preview-modal
// regression, and the reason three releases in a row never got published: the
// reconciler reports every managed file it rendered, unchanged ones included,
// and the modal is rendered from Before/After. An early return for an unchanged
// file left those entries with neither, so previewing a change that does not
// touch /etc/postfix/virtual (creating a domain) showed an empty diff box for
// it instead of "no change here". internal/mutations covers this end to end in
// TestPreviewIsADryRun, but that one needs a real SQLite driver (cgo), so the
// bug hid from every local run; this version runs everywhere.
func TestWriteFile_DryRunCarriesContentWhenNothingChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	if _, err := WriteFile(path, []byte("hello"), 0o644, false); err != nil {
		t.Fatal(err)
	}

	change, err := WriteFile(path, []byte("hello"), 0o644, true)
	if err != nil {
		t.Fatal(err)
	}
	if change.Action != "unchanged" {
		t.Errorf("want unchanged, got %s", change.Action)
	}
	if string(change.Before) != "hello" || string(change.After) != "hello" {
		t.Errorf("dry run reported no content for an unchanged file: before=%q after=%q",
			change.Before, change.After)
	}
}

// TestWriteFile_DryRunDoesNotTouchDisk — whatever the dry run reports, it must
// leave the file (and its mtime) alone.
func TestWriteFile_DryRunDoesNotTouchDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	if _, err := WriteFile(path, []byte("hello"), 0o644, false); err != nil {
		t.Fatal(err)
	}
	info1, _ := os.Stat(path)

	change, err := WriteFile(path, []byte("different"), 0o644, true)
	if err != nil {
		t.Fatal(err)
	}
	if change.Action != "update" {
		t.Errorf("want update, got %s", change.Action)
	}
	if string(change.Before) != "hello" || string(change.After) != "different" {
		t.Errorf("dry run must report both sides: before=%q after=%q", change.Before, change.After)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "hello" {
		t.Errorf("dry run rewrote the file: %q", got)
	}
	if info2, _ := os.Stat(path); !info1.ModTime().Equal(info2.ModTime()) {
		t.Error("dry run changed the file's mtime")
	}
}

// TestWriteFileOwnedAppliesOwnership — the Dovecot passwd-file has to end up
// owned by a group the auth process belongs to, and the ownership is applied to
// the *temp* file before the rename: a file that appears at its final path with
// the right bytes and an owner that cannot read them is a passdb that does not
// load, which is the login failure this exists to prevent.
//
// Chowning to ourselves is the one ownership change an unprivileged test can
// make, and it is enough: a chown that never happened, or one applied to the
// wrong path, comes back as ErrOwnership here.
func TestWriteFileOwnedAppliesOwnership(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no chown, so there is nothing to assert")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "users")

	change, err := WriteFileOwned(path, []byte("alice@example.com:{SSHA512}x\n"), 0o640,
		&Ownership{UID: os.Getuid(), GID: os.Getgid()}, false)
	if err != nil {
		t.Fatalf("WriteFileOwned with our own uid/gid: %v", err)
	}
	if change.Action != "create" {
		t.Errorf("action = %q, want create", change.Action)
	}

	// The ownership step must not undo the mode the caller asked for: 0640 is
	// what keeps the hashes away from everybody except root and the auth process.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat the written file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Errorf("mode = %04o, want 0640", got)
	}
}

// TestWriteFileOwnedReportsAFailedChown — a chown the panel is not allowed to
// make must not take the configuration down with it. The content is written, the
// daemons read it, and the caller is told with ErrOwnership, which the reconciler
// turns into a warning; refusing the whole sync would leave a server whose
// configuration never lands, over a permission the panel cannot grant itself.
func TestWriteFileOwnedReportsAFailedChown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no chown")
	}
	if os.Geteuid() == 0 {
		t.Skip("root may chown to anything, so this cannot fail here")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "users")

	// uid/gid 1 is daemon's on every Unix, and is not ours.
	change, err := WriteFileOwned(path, []byte("hello"), 0o600, &Ownership{UID: 1, GID: 1}, false)
	if !errors.Is(err, ErrOwnership) {
		t.Fatalf("err = %v, want ErrOwnership", err)
	}
	if change.Action != "create" {
		t.Errorf("action = %q, want create: the content is written either way", change.Action)
	}
	if got, readErr := os.ReadFile(path); readErr != nil || string(got) != "hello" {
		t.Errorf("content = %q (read error %v), want the bytes on disk despite the chown", got, readErr)
	}
}

// TestWriteFileLeavesOwnershipAlone — the other five managed files have no owner,
// and the wrapper the rest of the reconcile calls must not chown anything: it
// runs unprivileged on a build machine, where a chown would be an error rather
// than a no-op.
func TestWriteFileLeavesOwnershipAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	change, err := WriteFile(path, []byte("hello"), 0o640, false)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if change.Action != "create" {
		t.Errorf("action = %q, want create", change.Action)
	}

	// Windows reports 0666 for every file whatever mode it was created with, so
	// the mode is only worth asserting where there is one.
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %04o, want 0640", info.Mode().Perm())
	}
}
