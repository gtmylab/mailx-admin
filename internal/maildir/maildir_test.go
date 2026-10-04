package maildir

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func testMaildir(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "Maildir")
	for _, d := range []string{"cur", "new", "tmp", ".Sent/cur", ".Sent/new", ".Sent/tmp", ".Junk/cur"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	writeFile(t, filepath.Join(root, "cur", "a"), 100)
	writeFile(t, filepath.Join(root, "cur", "b"), 50)
	writeFile(t, filepath.Join(root, "new", "c"), 25)
	writeFile(t, filepath.Join(root, "tmp", "d"), 999)          // not a message
	writeFile(t, filepath.Join(root, ".Sent", "cur", "e"), 10)  // dot-folder message
	writeFile(t, filepath.Join(root, ".Sent", "tmp", "f"), 999) // dot-folder tmp
	writeFile(t, filepath.Join(root, ".Junk", "cur", "g"), 5)
	return root
}

func TestTotal(t *testing.T) {
	bytes, messages, err := Total(testMaildir(t))
	if err != nil {
		t.Fatalf("Total: %v", err)
	}
	if messages != 5 {
		t.Errorf("messages = %d, want 5", messages)
	}
	if want := int64(100 + 50 + 25 + 10 + 5); bytes != want {
		t.Errorf("bytes = %d, want %d", bytes, want)
	}
}

func TestTotalMissingRoot(t *testing.T) {
	if _, _, err := Total(filepath.Join(t.TempDir(), "nope", "Maildir")); err == nil {
		t.Error("Total succeeded for a missing root, want error")
	}
}

func TestFolders(t *testing.T) {
	folders, err := Folders(testMaildir(t))
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}

	got := map[string]Folder{}
	for _, f := range folders {
		got[f.Name] = f
	}

	if want := (Folder{Name: "INBOX", Bytes: 175, Messages: 3}); got["INBOX"] != want {
		t.Errorf("INBOX = %+v, want %+v", got["INBOX"], want)
	}
	if want := (Folder{Name: "Sent", Bytes: 10, Messages: 1}); got["Sent"] != want {
		t.Errorf("Sent = %+v, want %+v", got["Sent"], want)
	}
	if want := (Folder{Name: "Junk", Bytes: 5, Messages: 1}); got["Junk"] != want {
		t.Errorf("Junk = %+v, want %+v", got["Junk"], want)
	}

	// Sorted by bytes descending.
	if len(folders) == 0 || folders[0].Name != "INBOX" {
		t.Errorf("folders not sorted by size: %+v", folders)
	}
}
