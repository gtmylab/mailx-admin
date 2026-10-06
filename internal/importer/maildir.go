// Package importer imports mail from external sources (IMAP servers, mbox
// files, other maildirs) into a local Dovecot maildir, preserving folders,
// flags, read state and sent dates.
package importer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Flags are the message flags a maildir filename encodes.
type Flags struct {
	Seen     bool
	Flagged  bool
	Answered bool
	Draft    bool
	Deleted  bool
}

// String renders the maildir flag suffix in the conventional alphabetical order
// (D F R S T).
func (f Flags) String() string {
	var b strings.Builder
	if f.Draft {
		b.WriteByte('D')
	}
	if f.Flagged {
		b.WriteByte('F')
	}
	if f.Answered {
		b.WriteByte('R')
	}
	if f.Seen {
		b.WriteByte('S')
	}
	if f.Deleted {
		b.WriteByte('T')
	}
	return b.String()
}

func (f Flags) empty() bool { return f.String() == "" }

// Writer appends raw messages to a Dovecot maildir, chowning everything to the
// mailbox's uid/gid so Dovecot (which runs as vmail) can read what it writes.
type Writer struct {
	root string
	uid  int
	gid  int
	n    atomic.Int64
}

// NewWriter returns a Writer for the given maildir root (e.g. .../Maildir) and
// the ownership every file and folder must carry.
func NewWriter(root string, uid, gid int) *Writer {
	return &Writer{root: root, uid: uid, gid: gid}
}

// Put writes msg to folder ("" or "INBOX" is the inbox). flags become the
// maildir filename flags and date becomes the file mtime, which Dovecot reads
// as the message's INTERNALDATE.
func (w *Writer) Put(folder string, msg []byte, flags Flags, date time.Time) error {
	dir, err := w.folderDir(folder)
	if err != nil {
		return err
	}
	for _, sub := range []string{"cur", "new", "tmp"} {
		subDir := filepath.Join(dir, sub)
		if err := os.MkdirAll(subDir, 0o700); err != nil {
			return err
		}
		// MkdirAll creates missing directories as the panel's user (root); the
		// subdirectory must be chowned too, or Dovecot (vmail) cannot traverse
		// it and every access to the folder fails with "Internal error".
		_ = os.Chown(subDir, w.uid, w.gid)
	}
	_ = os.Chown(dir, w.uid, w.gid)

	id := fmt.Sprintf("%d.M%d.mailx", time.Now().UnixNano(), w.n.Add(1))
	var path string
	if flags.empty() {
		path = filepath.Join(dir, "new", id)
	} else {
		path = filepath.Join(dir, "cur", id+":2,"+flags.String())
	}
	if err := os.WriteFile(path, msg, 0o600); err != nil {
		return err
	}
	_ = os.Chown(path, w.uid, w.gid)
	if !date.IsZero() {
		_ = os.Chtimes(path, date, date)
	}
	return nil
}

// folderDir maps a folder name to its maildir directory. The inbox maps to the
// root; anything else becomes a dot-folder with the hierarchy delimiter (/)
// folded into dots.
func (w *Writer) folderDir(folder string) (string, error) {
	if folder == "" || folder == "INBOX" {
		return w.root, nil
	}
	parts := strings.Split(folder, "/")
	clean := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." {
			continue
		}
		clean = append(clean, p)
	}
	if len(clean) == 0 {
		return w.root, nil
	}
	return filepath.Join(w.root, "."+strings.Join(clean, ".")), nil
}
