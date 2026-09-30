package reconciler

import (
	"os"
	"path/filepath"
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
