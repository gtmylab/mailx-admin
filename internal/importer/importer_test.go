package importer

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap"
)

func TestSplitMbox(t *testing.T) {
	data := []byte(
		"From alice@example.com Mon Sep 27 10:00:00 2021\n" +
			"Subject: one\n\n" +
			"body one\n" +
			">From escaped\n" +
			"From bob@example.com Tue Sep 28 11:00:00 2021\n" +
			"Subject: two\n\n" +
			"body two\n",
	)
	msgs := SplitMbox(data)
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	first := string(msgs[0])
	if !strings.Contains(first, "Subject: one") {
		t.Errorf("first message missing its headers: %q", first)
	}
	if !strings.Contains(first, "From escaped") {
		t.Errorf(">From quoting not undone: %q", first)
	}
	if strings.Contains(first, ">From") {
		t.Errorf(">From left quoted: %q", first)
	}
	if !strings.Contains(string(msgs[1]), "Subject: two") {
		t.Errorf("second message wrong: %q", msgs[1])
	}
}

func TestMboxMeta(t *testing.T) {
	msg := []byte("Status: RO\nX-Status: AF\nDate: Mon, 27 Sep 2021 10:00:00 +0000\n\nbody\n")
	flags, date := mboxMeta(msg)
	if !flags.Seen {
		t.Error("Status: RO should mark the message seen")
	}
	if !flags.Answered || !flags.Flagged {
		t.Errorf("X-Status: AF should mark answered+flagged, got %+v", flags)
	}
	if date.IsZero() {
		t.Error("Date header not parsed")
	}
}

func TestWriterPut(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir, 0, 0)

	// A seen/flagged message goes into cur/; an unseen one into new/. (The
	// ":2,FS" flag suffix in the filename is not asserted here: it is illegal in
	// a Windows filename, so it can only be written on Linux; TestFlagsString
	// covers the flag encoding itself.)
	if err := w.Put("", []byte("hello"), Flags{Seen: true, Flagged: true}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "cur"))
	if err != nil {
		t.Fatalf("no cur dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("cur has %d files, want 1", len(entries))
	}

	// Unseen -> a dot-folder's new/ directory.
	if err := w.Put("Sent/2024", []byte("hi"), Flags{}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	entries, err = os.ReadDir(filepath.Join(dir, ".Sent.2024", "new"))
	if err != nil {
		t.Fatalf("no .Sent.2024/new dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf(".Sent.2024/new has %d files, want 1", len(entries))
	}
}

func TestFlagsString(t *testing.T) {
	if got := (Flags{Seen: true, Flagged: true}).String(); got != "FS" {
		t.Errorf("Flags.String() = %q, want FS", got)
	}
	if got := (Flags{Draft: true, Deleted: true, Seen: true}).String(); got != "DST" {
		t.Errorf("Flags.String() = %q, want DST", got)
	}
}

func TestFlagsFromName(t *testing.T) {
	f := flagsFromName("1234.M1.mailx:2,FRST")
	if !f.Flagged || !f.Answered || !f.Seen || !f.Deleted {
		t.Errorf("flags parsed wrong: %+v", f)
	}
}

// literalReader adapts a bytes.Reader to imap.Literal (io.Reader + Len).
type literalReader struct{ *bytes.Reader }

func (l *literalReader) Len() int { return l.Reader.Len() }

// TestMessageBody guards the IMAP body-fetch fix: Message.Body is keyed by
// *BodySectionName pointer identity, so a direct msg.Body[section] lookup never
// matches the key parsed from the server response and silently writes empty
// messages. messageBody must use GetBody, which matches by value.
func TestMessageBody(t *testing.T) {
	raw := []byte("Subject: hello\r\n\r\nbody here\r\n")
	msg := &imap.Message{}
	if err := msg.Parse([]interface{}{"BODY[]", &literalReader{bytes.NewReader(raw)}}); err != nil {
		t.Fatal(err)
	}

	section := &imap.BodySectionName{}
	got := messageBody(msg, section)
	if !bytes.Equal(got, raw) {
		t.Fatalf("messageBody = %q, want %q", got, raw)
	}

	// Lock in why the naive lookup was wrong: pointer identity must miss.
	if lit, ok := msg.Body[section]; ok {
		t.Errorf("msg.Body[section] matched by pointer identity: %v", lit)
	}
}
