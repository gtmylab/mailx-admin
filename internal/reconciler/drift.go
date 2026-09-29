package reconciler

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// defaultBackupDir is where pre-write copies of managed files are kept.
const defaultBackupDir = "/var/backups/mailx"

// maxDriftLines caps how many removed entries one file reports. A whole config
// file can be replaced in one go, and a warning with 400 lines in it is not a
// warning any more.
const maxDriftLines = 25

// Drift describes entries that exist on the server but not in the panel and that
// this sync therefore removed.
//
// This is the "I created a mailbox with useradd and the panel deleted it" case.
// The panel's files are managed as a whole, so a hand-added line in
// /etc/dovecot/users or /etc/postfix/virtual disappears on the next sync. It is
// reported here (and shown on the dashboard, and printed by `mailx-admin
// doctor`) instead of being deleted in silence, and the file it came from is
// preserved first.
type Drift struct {
	Path   string   `json:"path"`
	Count  int      `json:"count"`
	Lines  []string `json:"lines"`
	Backup string   `json:"backup,omitempty"`
}

// detectDrift reports the entry lines of before that are missing from after.
// It returns nil when nothing was dropped.
func detectDrift(path string, before, after []byte) *Drift {
	removed := removedEntries(before, after)
	if len(removed) == 0 {
		return nil
	}

	d := &Drift{Path: path, Count: len(removed)}
	if len(removed) > maxDriftLines {
		d.Lines = removed[:maxDriftLines]
	} else {
		d.Lines = removed
	}
	return d
}

// removedEntries is a multiset difference over the entry lines: a line that
// occurs twice before and once after is reported once.
func removedEntries(before, after []byte) []string {
	remaining := entryCounts(after)

	var out []string
	for _, line := range entryLines(before) {
		if remaining[line] > 0 {
			remaining[line]--
			continue
		}
		out = append(out, line)
	}
	return out
}

// entryLines returns the meaningful lines of a rendered config: no blanks, no
// comments. Those are the only lines that represent a mailbox, an alias or a
// listener.
func entryLines(b []byte) []string {
	var out []string
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func entryCounts(b []byte) map[string]int {
	counts := map[string]int{}
	for _, line := range entryLines(b) {
		counts[line]++
	}
	return counts
}

// backupCopy preserves data in dir and returns the path it was written to, or
// "" when it could not be preserved.
//
// The name carries the parent directory (postfix-virtual, dovecot-users),
// because several managed files share a base name and one backup must not
// overwrite another. The mode is 0600: the Dovecot passwd file is in here.
func backupCopy(dir, path string, data []byte) string {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	name := filepath.Base(filepath.Dir(path)) + "-" + filepath.Base(path)
	dst := filepath.Join(dir, name)
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return ""
	}
	return dst
}

// driftWarning is the operator-facing sentence for one Drift.
func driftWarning(d Drift) string {
	msg := fmt.Sprintf(
		"%s: %d entr%s on this server is not managed by the panel and was removed by this sync",
		filepath.Base(d.Path), d.Count, plural(d.Count, "y", "ies"))
	if d.Backup != "" {
		msg += fmt.Sprintf(" (the previous file was kept at %s)", d.Backup)
	} else {
		msg += " (and could not be backed up first)"
	}
	return msg + " — use \"Import from server\" to bring it into the panel."
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
