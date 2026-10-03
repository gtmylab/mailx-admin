package jobs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestMaildirUsage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Maildir")

	for _, d := range []string{"cur", "new", "tmp", ".Sent/cur", ".Sent/new", ".Sent/tmp", ".Junk/cur"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	// Delivered messages (cur/new), in-flight (tmp), and dot-folders.
	writeFile(t, filepath.Join(root, "cur", "a"), 100)
	writeFile(t, filepath.Join(root, "cur", "b"), 50)
	writeFile(t, filepath.Join(root, "new", "c"), 25)
	writeFile(t, filepath.Join(root, "tmp", "d"), 999)          // not a message
	writeFile(t, filepath.Join(root, ".Sent", "cur", "e"), 10)  // dot-folder message
	writeFile(t, filepath.Join(root, ".Sent", "tmp", "f"), 999) // dot-folder tmp

	bytes, messages, err := maildirUsage(root)
	if err != nil {
		t.Fatalf("maildirUsage: %v", err)
	}
	if messages != 4 {
		t.Errorf("messages = %d, want 4", messages)
	}
	if want := int64(100 + 50 + 25 + 10); bytes != want {
		t.Errorf("bytes = %d, want %d", bytes, want)
	}
}

func TestMaildirUsageMissingRoot(t *testing.T) {
	if _, _, err := maildirUsage(filepath.Join(t.TempDir(), "nope", "Maildir")); err == nil {
		t.Error("maildirUsage succeeded for a missing root, want error")
	}
}

func TestNextDelayAt(t *testing.T) {
	loc := time.UTC

	cases := []struct {
		name      string
		now       time.Time
		hour, min int
		want      time.Duration
	}{
		{"future today", time.Date(2026, 1, 1, 1, 0, 0, 0, loc), 3, 0, 2 * time.Hour},
		{"already passed", time.Date(2026, 1, 1, 5, 0, 0, 0, loc), 3, 0, 22 * time.Hour},
		{"exactly now rolls to tomorrow", time.Date(2026, 1, 1, 3, 0, 0, 0, loc), 3, 0, 24 * time.Hour},
		{"midnight boundary", time.Date(2026, 1, 1, 23, 30, 0, 0, loc), 0, 0, 30 * time.Minute},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextDelayAt(tc.now, tc.hour, tc.min); got != tc.want {
				t.Errorf("nextDelayAt = %v, want %v", got, tc.want)
			}
		})
	}
}
