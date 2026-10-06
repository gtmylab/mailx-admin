package importer

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

// IMAPConfig is a source IMAP server. It covers Google Workspace (app password),
// Microsoft 365 (app password) and any Mailcow/Mailu/iRedMail host.
type IMAPConfig struct {
	Host     string
	Port     int
	TLSMode  string // "", "starttls" or "tls"
	Username string
	Password string
}

// ImportIMAP connects to the server, lists every folder and fetches each
// message with its flags and internal date, writing them into w.
func ImportIMAP(ctx context.Context, cfg IMAPConfig, w *Writer) (*Result, error) {
	if cfg.Port == 0 {
		if cfg.TLSMode == "tls" {
			cfg.Port = 993
		} else {
			cfg.Port = 143
		}
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))

	c, err := dialIMAP(cfg.TLSMode, addr)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer c.Logout()

	if err := c.Login(cfg.Username, cfg.Password); err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}

	res := &Result{Folders: map[string]int{}}

	boxes := make(chan *imap.MailboxInfo, 32)
	listDone := make(chan error, 1)
	go func() { listDone <- c.List("", "*", boxes) }()

	var names []string
	for b := range boxes {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		names = append(names, b.Name)
	}
	if err := <-listDone; err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}

	for _, name := range names {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Some folders exist only as namespace nodes and cannot be selected.
		if _, err := c.Select(name, true); err != nil {
			continue
		}
		n, err := importFolder(ctx, c, name, w)
		if err != nil {
			return nil, err
		}
		res.Folders[name] += n
	}
	return res, nil
}

// dialIMAP opens the connection with the requested encryption.
func dialIMAP(mode, addr string) (*client.Client, error) {
	switch mode {
	case "tls":
		return client.DialTLS(addr, nil)
	case "starttls":
		c, err := client.Dial(addr)
		if err != nil {
			return nil, err
		}
		if err := c.StartTLS(nil); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	default:
		return client.Dial(addr)
	}
}

// importFolder fetches every message in the selected folder and writes it.
func importFolder(ctx context.Context, c *client.Client, name string, w *Writer) (int, error) {
	section := &imap.BodySectionName{}
	items := []imap.FetchItem{section.FetchItem(), imap.FetchFlags, imap.FetchInternalDate}

	seqset := new(imap.SeqSet)
	seqset.AddRange(1, 0) // 1:* — every message

	messages := make(chan *imap.Message, 64)
	done := make(chan error, 1)
	go func() { done <- c.Fetch(seqset, items, messages) }()

	n := 0
	for msg := range messages {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		flags := Flags{
			Seen:     hasFlag(msg.Flags, imap.SeenFlag),
			Flagged:  hasFlag(msg.Flags, imap.FlaggedFlag),
			Answered: hasFlag(msg.Flags, imap.AnsweredFlag),
			Draft:    hasFlag(msg.Flags, imap.DraftFlag),
			Deleted:  hasFlag(msg.Flags, imap.DeletedFlag),
		}
		var date time.Time
		if !msg.InternalDate.IsZero() {
			date = msg.InternalDate
		}
		var body []byte
		if lit, ok := msg.Body[section]; ok {
			body, _ = io.ReadAll(lit)
		}
		if err := w.Put(name, body, flags, date); err != nil {
			return n, err
		}
		n++
	}
	return n, <-done
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if strings.EqualFold(f, want) {
			return true
		}
	}
	return false
}
