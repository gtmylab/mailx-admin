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
// for ownership. It dispatches on the source type.
func Import(ctx context.Context, src Source, dst string, uid, gid int) (*Result, error) {
	w := NewWriter(dst, uid, gid)
	switch {
	case src.IMAP != nil:
		return ImportIMAP(ctx, *src.IMAP, w)
	case src.MboxPath != "":
		return ImportMbox(ctx, src.MboxPath, w)
	case src.MaildirPath != "":
		return ImportMaildir(ctx, src.MaildirPath, w)
	default:
		return nil, fmt.Errorf("no import source configured")
	}
}
