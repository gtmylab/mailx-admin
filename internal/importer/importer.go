package importer

import (
	"context"
	"fmt"
	"sort"
)

// Source describes where to import from. Exactly one field is used.
type Source struct {
	IMAP        *IMAPConfig
	MboxPath    string // a single mbox file, or a directory of mbox files
	MaildirPath string // a source maildir to copy
}

// Summary returns a short human-readable description of the source.
func (s Source) Summary() string {
	switch {
	case s.IMAP != nil:
		return "IMAP " + s.IMAP.Username + "@" + s.IMAP.Host
	case s.MboxPath != "":
		return "mbox " + s.MboxPath
	case s.MaildirPath != "":
		return "Maildir " + s.MaildirPath
	default:
		return "unknown"
	}
}

// Progress is a live update from a running import: an optional log line, the
// current folder and the cumulative message counts.
type Progress struct {
	Log      string // human-readable event ("" = no new event)
	Folder   string // current folder ("" = unchanged)
	Messages int    // cumulative messages written
	Total    int    // cumulative total expected (0 = unknown)
}

// Result reports how many messages were imported per folder.
type Result struct {
	Folders map[string]int
}

// Total returns the number of messages imported across every folder.
func (r *Result) Total() int {
	n := 0
	for _, c := range r.Folders {
		n += c
	}
	return n
}

// FolderCount is one folder's imported-message count, for the UI. The inbox is
// reported as "INBOX" rather than the empty string.
type FolderCount struct {
	Name  string
	Count int
}

// SortedFolders returns the per-folder counts sorted by name.
func (r *Result) SortedFolders() []FolderCount {
	names := make([]string, 0, len(r.Folders))
	for n := range r.Folders {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]FolderCount, 0, len(names))
	for _, n := range names {
		display := n
		if display == "" {
			display = "INBOX"
		}
		out = append(out, FolderCount{Name: display, Count: r.Folders[n]})
	}
	return out
}

// Import runs the import described by src into the maildir at dst, using uid/gid
// for ownership. report receives progress events and may be nil.
func Import(ctx context.Context, src Source, dst string, uid, gid int, report func(Progress)) (*Result, error) {
	w := NewWriter(dst, uid, gid)
	switch {
	case src.IMAP != nil:
		return ImportIMAP(ctx, *src.IMAP, w, report)
	case src.MboxPath != "":
		return ImportMbox(ctx, src.MboxPath, w, report)
	case src.MaildirPath != "":
		return ImportMaildir(ctx, src.MaildirPath, w, report)
	default:
		return nil, fmt.Errorf("no import source configured")
	}
}
