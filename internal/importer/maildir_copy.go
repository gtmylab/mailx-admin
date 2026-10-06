package importer

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ImportMaildir copies a source maildir into dst, preserving flags (read from
// each filename) and mtimes. It is the filesystem-access path for Mailcow,
// Mailu and iRedMail migrations, where the source host is reachable and its
// maildir can be mounted or copied locally. report receives progress events
// (may be nil).
func ImportMaildir(ctx context.Context, srcRoot string, w *Writer, report func(Progress)) (*Result, error) {
	emit := func(p Progress) {
		if report != nil {
			report(p)
		}
	}
	res := &Result{Folders: map[string]int{}}

	emit(Progress{Log: "Copying " + srcRoot + "..."})

	// First pass: count messages so the progress bar has a total.
	total := 0
	_ = filepath.WalkDir(srcRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		parent := filepath.Base(filepath.Dir(path))
		if parent == "cur" || parent == "new" {
			total++
		}
		return nil
	})

	cumulative := 0
	err := filepath.WalkDir(srcRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		parent := filepath.Base(filepath.Dir(path))
		if parent != "cur" && parent != "new" {
			return nil
		}

		rel, _ := filepath.Rel(srcRoot, filepath.Dir(path))
		folder := folderFromRel(rel)
		flags := flagsFromName(d.Name())

		var mt time.Time
		if info, err := d.Info(); err == nil {
			mt = info.ModTime()
		}

		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := w.Put(folder, b, flags, mt); err != nil {
			return err
		}
		cumulative++
		res.Folders[folder]++
		emit(Progress{Folder: folder, Messages: cumulative, Total: total})
		return nil
	})
	if err != nil {
		return nil, err
	}
	emit(Progress{Log: fmt.Sprintf("Import complete: %d messages.", cumulative), Messages: cumulative, Total: total})
	return res, nil
}

// folderFromRel maps a message's directory relative to the maildir root to a
// folder name: "cur" -> "", ".Sent/cur" -> "Sent".
func folderFromRel(rel string) string {
	rel = filepath.ToSlash(rel)
	rel = strings.TrimSuffix(rel, "/cur")
	rel = strings.TrimSuffix(rel, "/new")
	if rel == "" || rel == "." {
		return ""
	}
	return strings.ReplaceAll(strings.TrimPrefix(rel, "."), ".", "/")
}

// flagsFromName reads the flags out of a maildir filename's ":2,FSRDT" suffix.
func flagsFromName(name string) Flags {
	var f Flags
	if i := strings.LastIndex(name, ":2,"); i >= 0 {
		for _, c := range name[i+3:] {
			switch c {
			case 'S':
				f.Seen = true
			case 'F':
				f.Flagged = true
			case 'R':
				f.Answered = true
			case 'D':
				f.Draft = true
			case 'T':
				f.Deleted = true
			}
		}
	}
	return f
}
