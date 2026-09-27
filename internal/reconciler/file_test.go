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
