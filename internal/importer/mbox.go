package importer

import (
	"bytes"
	"context"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SplitMbox splits an mbox (mboxrd) byte stream into individual messages. The
// leading "From " separator line is dropped and ">From " quoting is undone, so
// each returned slice is a standalone RFC 5322 message.
func SplitMbox(data []byte) [][]byte {
	var msgs [][]byte
	var cur []byte
	started := false
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("From ")) {
			if started {
				msgs = append(msgs, cur)
				cur = nil
			}
			started = true
			continue
		}
		if !started {
			continue
		}
		if bytes.HasPrefix(line, []byte(">From ")) {
			line = line[1:]
		}
		cur = append(cur, line...)
	}
	if started && len(cur) > 0 {
		msgs = append(msgs, cur)
	}
	return msgs
}

// mboxMeta reads a message's read-state flags and sent date from its headers.
// cPanel and most mbox exporters record read state in "Status:" and flags in
// "X-Status:"; the sent date is the "Date:" header.
func mboxMeta(msg []byte) (Flags, time.Time) {
	var f Flags
	var date time.Time
	m, err := mail.ReadMessage(bytes.NewReader(msg))
	if err != nil {
		return f, date
	}
	status := m.Header.Get("Status")
	if strings.Contains(status, "R") || strings.Contains(status, "O") {
		f.Seen = true
	}
	for _, c := range m.Header.Get("X-Status") {
		switch c {
		case 'A':
			f.Answered = true
		case 'F':
			f.Flagged = true
		case 'D':
			f.Deleted = true
		case 'T':
			f.Draft = true
		}
	}
	if d, err := mail.ParseDate(m.Header.Get("Date")); err == nil {
		date = d
	}
	return f, date
}

// ImportMbox reads an mbox file (or a directory of mbox files) and writes the
// messages into dst. A single file goes into the inbox; a directory imports
// each file as its own folder named after the file.
func ImportMbox(ctx context.Context, path string, w *Writer) (*Result, error) {
	res := &Result{Folders: map[string]int{}}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	type entry struct {
		folder string
		path   string
	}
	var files []entry
	if info.IsDir() {
		items, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			if it.IsDir() {
				continue
			}
			files = append(files, entry{
				folder: strings.TrimSuffix(it.Name(), filepath.Ext(it.Name())),
				path:   filepath.Join(path, it.Name()),
			})
		}
	} else {
		files = append(files, entry{folder: "", path: path})
	}

	for _, f := range files {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		data, err := os.ReadFile(f.path)
		if err != nil {
			return nil, err
		}
		for _, msg := range SplitMbox(data) {
			flags, date := mboxMeta(msg)
			if err := w.Put(f.folder, msg, flags, date); err != nil {
				return nil, err
			}
			res.Folders[f.folder]++
		}
	}
	return res, nil
}
