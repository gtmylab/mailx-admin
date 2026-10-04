// Package maildir measures how much of a Maildir is used, both as a total and
// per folder. It is read-only: it never creates, moves or deletes anything.
package maildir

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// Total sums the sizes of the delivered messages under a Maildir and counts
// them. Only cur/ and new/ hold delivered mail — tmp/ is in-flight — and
// dot-folders such as .Sent are Maildirs too, so the walk counts them the same
// way. The Maildir/ root itself holds no messages.
func Total(root string) (bytes int64, messages int, err error) {
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !isMessage(path, d) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		messages++
		bytes += info.Size()
		return nil
	})
	return bytes, messages, err
}

// Folder is one folder's usage inside a Maildir.
type Folder struct {
	Name     string // "INBOX", "Sent", "Junk", ... (dot prefix stripped)
	Bytes    int64
	Messages int
}

// Folders walks a Maildir and returns per-folder usage, sorted by bytes
// descending so the heaviest folder is first.
func Folders(root string) ([]Folder, error) {
	agg := map[string]*Folder{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !isMessage(path, d) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		name := folderName(root, path)
		f := agg[name]
		if f == nil {
			f = &Folder{Name: name}
			agg[name] = f
		}
		f.Bytes += info.Size()
		f.Messages++
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]Folder, 0, len(agg))
	for _, f := range agg {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// isMessage reports whether d is a delivered message: a regular file whose
// parent directory is cur/ or new/ (not tmp/, and not a dot-folder itself).
func isMessage(path string, d fs.DirEntry) bool {
	if d.IsDir() {
		return false
	}
	parent := filepath.Base(filepath.Dir(path))
	return parent == "cur" || parent == "new"
}

// folderName maps a message path to its folder name. A message directly under
// <root>/cur or <root>/new belongs to the inbox; one under <root>/.Sent/cur
// belongs to "Sent".
func folderName(root, path string) string {
	dir := filepath.Dir(path)
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return "INBOX"
	}
	rel = filepath.ToSlash(rel)
	if rel == "cur" || rel == "new" || rel == "." {
		return "INBOX"
	}
	// ".Sent/cur" -> ".Sent" -> "Sent"
	name := strings.SplitN(rel, "/", 2)[0]
	return strings.TrimPrefix(name, ".")
}
